/* ------------------------------------------------------------------------- */
/*                                                                           */
/*   The contents of this file are subject to the Mozilla Public License     */
/*   Version 1.1 (the "License"); you may not use this file except in        */
/*   compliance with the License. You may obtain a copy of the License at    */
/*   http://www.mozilla.org/MPL/                                             */
/*                                                                           */
/*   Software distributed under the License is distributed on an "AS IS"     */
/*   basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the */
/*   License for the specific language governing rights and limitations      */
/*   under the License.                                                      */
/*                                                                           */
/*   The Original Code is SPB.                                               */
/*                                                                           */
/*   The Initial Developers of the Original Code are VMware, Inc.            */
/*   Copyright (c) 2011-2011 VMware, Inc.  All rights reserved.              */
/*                                                                           */
/* ------------------------------------------------------------------------- */

#define _BSD_SOURCE

#include <Judy.h>
#include <arpa/inet.h>
#include <erl_driver.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "spb.h"

#define FALSE                  0
#define TRUE                   1

#define OK                     1
#define READER_ERROR          -1

#define ATOM_SPEC_LEN          8
#define READER_ERROR_SPEC_LEN  13
#define SOCKET_ERROR_SPEC_LEN  15
#define OK_FD_SPEC_LEN         12
#define FD_DATA_SPEC_LEN       16
#define FD_CLOSED_SPEC_LEN     12
#define FD_BAD_SPEC_LEN        12

#define LISTEN_SOCKET 1
#define CONNECTED_SOCKET 2

#define WRITE_COMMAND_PREFIX_LENGTH 9
#define DEFAULT_IOV_MAX 16

typedef struct {
  ErlDrvPort     port;               /* driver port                                    */
  ErlDrvTermData pid;                /* driver pid                                     */

  /* {'spb_event', Port, 'no_such_command'}                                            */
  ErlDrvTermData *no_such_command_atom_spec;

  /* {'spb_event', Port, 'ok'}                                                         */
  ErlDrvTermData *ok_atom_spec;

  /* {'spb_event', Port, {'reader_error', "string"}}                                   */
  ErlDrvTermData *reader_error_spec; /* terms for errors from reader                   */

  /* {'spb_event', Port, {'socket_error', Fd, "string"}}                               */
  ErlDrvTermData *socket_error_spec; /* terms for errors from socket                   */

  /* {'spb_event', Port, {'ok', Fd}}                                                   */
  ErlDrvTermData *ok_fd_spec;        /* terms for ok results including a fd            */

  /* {'spb_event', Port, {'data', Fd, Binary}}                                         */
  ErlDrvTermData *fd_data_spec;      /* terms for results including a fd and data      */

  /* {'spb_event', Port, {'closed', Fd}}                                               */
  ErlDrvTermData *fd_closed_spec;    /* terms for sending to a pid on socket close     */

  /* {'spb_event', Port, {'badarg', Fd}}                                               */
  ErlDrvTermData *fd_bad_spec;       /* terms for sending to a pid on general error    */

  struct ev_loop *epoller;           /* our ev loop                                    */
  ErlDrvTid      tid;                /* the thread running our ev loop                 */
  ev_async       *async_watcher;     /* the async watcher used to talk to our thread   */
  ErlDrvMutex    *command_mutex;     /* mutex for safely communicating with our thread */
  Pvoid_t        command_queue;      /* the command being sent to our thread           */
  Pvoid_t        sockets;            /* the Judy array to store state of FDs in        */
  ErlDrvMutex    *sockets_mutex;     /* mutex for safely accessing sockets             */
  ErlDrvCond     *cond;              /* conditional for signalling from thread to drv  */
  int            iov_max;
  int            socket_entry_serial;
} SpbData;

typedef struct {
  ErlIOVec *ev;
  size_t row;
  size_t column;
  ReaderError last_error;
} Reader;

typedef struct {
  Pvoid_t acceptors;
} ListenSocket;

typedef struct {
  int64_t quota;
  int64_t pending_writes;
  ErlDrvMutex *mutex;
  ErlIOVec *ev;
  ev_io *watcher;
} ConnectedSocket;

typedef union {
  ListenSocket listen_socket;
  ConnectedSocket connected_socket;
} Socket;

typedef struct {
  uint8_t type;
  int fd;
  ev_io *watcher;
  ErlDrvTermData pid;
  Socket socket;
  int serial;
} SocketEntry;

typedef struct {
  int            fd;
  uint8_t        type;
  uint8_t        done;
  uint8_t        free_when_done;
  int64_t        value;
  SpbData        *sd;
  ErlIOVec       *ev;
  ErlDrvCond     *cond;
  ErlDrvMutex    *mutex;
  ErlDrvTermData pid;
} SocketAction;

uint8_t spb_invalid_command = SPB_INVALID_COMMAND;


/**********************
 *  Reader Functions  *
 **********************/

/* only used in debugging */
void dump_ev(const ErlIOVec *const ev) {
  printf("total size: %d\r\nvec len: %d\r\n", ev->size, ev->vsize);
  int idx;
  for (idx = 0; idx < ev->vsize; ++idx) {
    printf("iov[%d] = ", idx);
    SysIOVec iov = ev->iov[idx];
    printf("[base = %p, len = %zd]\r\n", iov.iov_base, iov.iov_len);
    printf("binv[%d] = ", idx);
    if (NULL == ev->binv[idx]) {
      printf("NULL\r\n");
    } else {
      ErlDrvBinary* bin = ev->binv[idx];
      printf("[orig_bytes = %p; orig_size = %ld]\r\n",
             bin->orig_bytes, bin->orig_size);
    }
  }
  printf("dump done\r\n");
}

void make_reader(ErlIOVec *const ev, Reader *const reader) {
  reader->ev = ev;
  reader->row = 1; /* row 0 is reserved for headers */
  reader->column = 0;
  reader->last_error = READER_NO_ERROR;
}

int read_simple_thing(Reader *const reader, const char **const result,
                      const size_t size) {
  size_t row = reader->row;
  size_t column = reader->column;
  const long data_left_in_current_row =
    (reader->ev->binv[row]->orig_size) - column;
  if (data_left_in_current_row == 0) {
    ++row;
    if (row == reader->ev->vsize) {
      reader->last_error = READER_READ_ALL_DATA;
      return FALSE; /* run out of data */
    } else {
      reader->row = row;
      reader->column = 0;
      return read_simple_thing(reader, result, size);
    }
  } else if (data_left_in_current_row < size) {
    reader->last_error = READER_PACKING_ERROR;
    return FALSE; /* packing error! */
  } else {
    *result = (reader->ev->binv[row]->orig_bytes) + column;
    column += size;
    reader->column = column;
    return TRUE;
  }
}

int read_uint8(Reader *const reader, const uint8_t **const result) {
  return read_simple_thing(reader, (const char **const)result, sizeof(uint8_t));
}

int read_int8(Reader *const reader, const int8_t **const result) {
  return read_simple_thing(reader, (const char **const)result, sizeof(int8_t));
}

int read_uint16(Reader *const reader, const uint16_t **const result) {
  return
    read_simple_thing(reader, (const char **const)result, sizeof(uint16_t));
}

int read_int32(Reader *const reader, const int32_t **const result) {
  return read_simple_thing(reader, (const char **const)result, sizeof(int32_t));
}

int read_uint64(Reader *const reader, const uint64_t **const result) {
  return
    read_simple_thing(reader, (const char **const)result, sizeof(uint64_t));
}

int read_int64(Reader *const reader, const int64_t **const result) {
  return read_simple_thing(reader, (const char **const)result, sizeof(int64_t));
}

int read_binary(Reader *const reader, const char **const result,
                const uint64_t **const binlen) {
  if (read_simple_thing(reader, (const char **const)binlen, sizeof(uint64_t))) {
    return read_simple_thing(reader, result, **binlen);
  } else {
    return 1;
  }
}

void return_reader_error(SpbData *const sd, const Reader *const reader) {
  const char* error_str;
  if (NULL == reader) {
    error_str = "Null reader";
  } else {
    switch (reader->last_error) {
    case READER_NO_ERROR:
      error_str = "No error";
      break;
    case READER_READ_ALL_DATA:
      error_str = "Exhausted all supplied data";
      break;
    case READER_PACKING_ERROR:
      error_str = "Packing error";
      break;
    default:
      error_str = "Unknown error";
    }
  }
  sd->reader_error_spec[7] = (ErlDrvTermData)error_str;
  sd->reader_error_spec[8] = (ErlDrvUInt)strlen(error_str);
  driver_send_term(sd->port, sd->pid, sd->reader_error_spec, READER_ERROR_SPEC_LEN);
  sd->reader_error_spec[7] = (ErlDrvTermData)NULL;
  sd->reader_error_spec[8] = 0;
}


/**************************
 *  Misc Synchronisation  *
 **************************/

void await_non_null(const void *const *const ptr, SpbData *const sd) {
  erl_drv_mutex_lock(sd->command_mutex);
  while (NULL != ptr && NULL == *ptr)
    erl_drv_cond_wait(sd->cond, sd->command_mutex);
  erl_drv_mutex_unlock(sd->command_mutex);
}

void await_epoller(SpbData *const sd) {
  await_non_null((const void const* const*)&(sd->epoller), sd);
}

void mark_done_and_signal(SocketAction *sa) {
  if (NULL != sa->mutex)
    erl_drv_mutex_lock(sa->mutex);
  sa->done = TRUE;
  if (NULL != sa->cond)
    erl_drv_cond_signal(sa->cond);
  if (NULL != sa->mutex)
    erl_drv_mutex_unlock(sa->mutex);
  if (sa->free_when_done)
    driver_free(sa);
}

void await_done(SocketAction *sa) {
  if (NULL == sa->mutex || NULL == sa->cond)
    return;
  erl_drv_mutex_lock(sa->mutex);
  while (! sa->done)
    erl_drv_cond_wait(sa->cond, sa->mutex);
  erl_drv_mutex_unlock(sa->mutex);
}

/*****************************
 *  Command Queue Functions  *
 *****************************/

void socket_action_new(SocketAction *const sa,
                       const uint8_t type, const int fd,
                       ErlDrvCond *const cond, ErlDrvMutex *const mutex,
                       ErlDrvTermData pid, SpbData *const sd) {
  sa->fd = fd;
  sa->type = type;
  sa->done = FALSE;
  sa->free_when_done = FALSE;
  sa->value = 0;
  sa->sd = sd;
  sa->ev = NULL;
  sa->cond = cond;
  sa->mutex = mutex;
  sa->pid = pid;
}

SocketAction *socket_action_alloc(const uint8_t type, const int fd,
                                  ErlDrvCond *const cond,
                                  ErlDrvMutex *const mutex,
                                  ErlDrvTermData pid, SpbData *const sd) {
  SocketAction *sa = (SocketAction *)driver_alloc(sizeof(SocketAction));
  if (NULL == sa)
    driver_failure(sd->port, -1);
  socket_action_new(sa, type, fd, cond, mutex, pid, sd);
  sa->free_when_done = TRUE;
  return sa;
}

void command_enqueue_and_notify(SocketAction *const sa, SpbData *const sd) {
  erl_drv_mutex_lock(sd->command_mutex);
  SocketAction **sa_ptr = NULL;
  Word_t index = -1;
  /* find the last present index in the command_queue */
  JLL(sa_ptr, sd->command_queue, index);
  if (NULL == sa_ptr)
    index = 0;
  else
    ++index;
  JLI(sa_ptr, sd->command_queue, index);
  *sa_ptr = sa;
  erl_drv_mutex_unlock(sd->command_mutex);
  ev_async_send(sd->epoller, sd->async_watcher);
}

void command_dequeue(SocketAction **sa, SpbData *const sd) {
  erl_drv_mutex_lock(sd->command_mutex);
  SocketAction **sa_ptr = NULL;
  Word_t index = 0;
  /* find the first item in the command_queue */
  JLF(sa_ptr, sd->command_queue, index);
  if (NULL != sa_ptr && NULL != *sa_ptr) {
    *sa = *sa_ptr;
    int rc = 0;
    JLD(rc, sd->command_queue, index);
  } else {
    *sa = NULL;
  }
  erl_drv_mutex_unlock(sd->command_mutex);
}


/****************************
 *  Sending back to Erlang  *
 ****************************/

void return_socket_closed_pid(SpbData *const sd, const int fd,
                              ErlDrvTermData pid) {
  sd->fd_closed_spec[7] = (ErlDrvSInt)fd;
  driver_send_term(sd->port, pid, sd->fd_closed_spec, FD_CLOSED_SPEC_LEN);
  sd->fd_closed_spec[7] = 0;
}

void return_socket_bad_pid(SpbData *const sd, const int fd,
                           ErlDrvTermData pid) {
  sd->fd_bad_spec[7] = (ErlDrvSInt)fd;
  driver_send_term(sd->port, pid, sd->fd_bad_spec, FD_BAD_SPEC_LEN);
  sd->fd_bad_spec[7] = 0;
}

void return_socket_error_str_pid(SpbData *const sd, const int fd,
                                 const char* error_str, ErlDrvTermData pid) {
  sd->socket_error_spec[7] = (ErlDrvSInt)fd;
  sd->socket_error_spec[9] = (ErlDrvTermData)error_str;
  sd->socket_error_spec[10] = (ErlDrvUInt)strlen(error_str);
  driver_send_term(sd->port, pid, sd->socket_error_spec, SOCKET_ERROR_SPEC_LEN);
  sd->socket_error_spec[7] = (ErlDrvSInt)0;
  sd->socket_error_spec[9] = (ErlDrvTermData)NULL;
  sd->socket_error_spec[10] = 0;
}

void return_socket_error_pid(SpbData *const sd, const int fd, const int error,
                             ErlDrvTermData pid) {
  return_socket_error_str_pid(sd, fd, strerror(error), pid);
}

void return_ok_fd_pid(SpbData *const sd, ErlDrvTermData pid, const int fd) {
  sd->ok_fd_spec[7] = fd;
  driver_send_term(sd->port, pid, sd->ok_fd_spec, OK_FD_SPEC_LEN);
  sd->ok_fd_spec[7] = 0;
}


/**********************
 *  Socket Functions  *
 **********************/

int setnonblock(const int fd) { /* and turn off nagle */
  int flags = fcntl(fd, F_GETFL);
  flags |= O_NONBLOCK;
  flags |= O_NDELAY;
  return fcntl(fd, F_SETFL, flags);
}

void socket_listen(SpbData *const sd, Reader *const reader) {
  const char *address = NULL;
  const uint64_t *address_len = NULL;

  if (! read_binary(reader, &address, &address_len)) {
    return_reader_error(sd, reader);
    return;
  }

  const uint16_t *port;
  if (! read_uint16(reader, &port)) {
    return_reader_error(sd, reader);
    return;
  }

  struct sockaddr_in listen_address;
  const int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (listen_fd < 0) {
    return_socket_error_pid(sd, 0, errno, sd->pid);
    return;
  }

  /* strings coming from Erlang are not zero terminated, and the
     length won't include the 0 stop byte, so copy into a new array,
     ensuring we have a stop byte at the end. */
  char *const address_null = (char*) driver_alloc((*address_len)+1);
  if (NULL == address_null) {
    return_reader_error(sd, reader);
    return;
  }

  address_null[(*address_len)] = '\0';
  strncpy(address_null, address, *address_len);

  memset(&listen_address, 0, sizeof(listen_address));

  listen_address.sin_family = AF_INET;
  listen_address.sin_port = htons(*port);
  const int inet_aton_res = inet_aton(address_null, &(listen_address.sin_addr));
  driver_free(address_null);

  if (0 == inet_aton_res) { /* why does inet_aton return 0 on FAILURE?! */
    return_socket_error_pid(sd, 0, errno, sd->pid);
    return;
  }

  if (0 > bind(listen_fd,
               (struct sockaddr *)&listen_address,
               sizeof(listen_address))) {
    return_socket_error_pid(sd, 0, errno, sd->pid);
    return;
  }

  /* listen for incoming connections. set backlog to 128 */
  if (0 > listen(listen_fd, 128)) {
    return_socket_error_pid(sd, 0, errno, sd->pid);
    return;
  }

  const int reuse = 1;
  /* turn on reuseaddr */
  if (0 > setsockopt(listen_fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &reuse,
                     sizeof(reuse))) {
    return_socket_error_pid(sd, 0, errno, sd->pid);
    return;
  }

  /* put socket into nonblocking mode - needed for libev */
  if (0 > setnonblock(listen_fd)) {
    return_socket_error_pid(sd, 0, errno, sd->pid);
    return;
  }

  SocketAction *sa = socket_action_alloc(SPB_ASYNC_LISTEN, listen_fd,
                                         NULL, NULL, sd->pid, sd);
  command_enqueue_and_notify(sa, sd);
}

void socket_close(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  if (! read_int64(reader, &fd64_ptr)) {
    return_reader_error(sd, reader);
    return;
  }
  SocketAction *sa = socket_action_alloc(SPB_ASYNC_CLOSE, (int)*fd64_ptr,
                                         NULL, NULL, sd->pid, sd);
  command_enqueue_and_notify(sa, sd);
}

void socket_accept(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  if (! read_int64(reader, &fd64_ptr)) {
    return_reader_error(sd, reader);
    return;
  }
  SocketAction *sa = socket_action_alloc(SPB_ASYNC_ACCEPT, (int)*fd64_ptr,
                                         NULL, NULL, sd->pid, sd);
  command_enqueue_and_notify(sa, sd);
}

void socket_recv(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  const int64_t *bytes_ptr = NULL;
  if (! (read_int64(reader, &fd64_ptr) && read_int64(reader, &bytes_ptr))) {
    return_reader_error(sd, reader);
    return;
  }
  SocketAction *sa = socket_action_alloc(SPB_ASYNC_RECV, (int)*fd64_ptr,
                                         NULL, NULL, sd->pid, sd);
  sa->value = *bytes_ptr;
  command_enqueue_and_notify(sa, sd);
}

void async_socket_write(SocketAction *const sa) {
  const int fd = sa->fd;
  SpbData *const sd = sa->sd;
  mark_done_and_signal(sa);

  SocketEntry **se_ptr = NULL;
  SocketEntry *se = NULL;

  erl_drv_mutex_lock(sd->sockets_mutex);
  JLG(se_ptr, sd->sockets, fd); /* find the SocketEntry for fd */

  if (NULL != se_ptr && NULL != *se_ptr &&
      CONNECTED_SOCKET == (*se_ptr)->type) {
    se = *se_ptr;
    erl_drv_mutex_lock(se->socket.connected_socket.mutex);
    erl_drv_mutex_unlock(sd->sockets_mutex);
    int64_t ready = se->socket.connected_socket.pending_writes;
    if (0 == ready) {
      /* huh, nothing to write after all. Oh well */
      erl_drv_mutex_unlock(se->socket.connected_socket.mutex);
    } else {
      ErlIOVec *ev_ptr = se->socket.connected_socket.ev;
      /* printf("before:\r\n"); */
      /* dump_ev(ev_ptr); */

      int iovcnt = ev_ptr->vsize > sd->iov_max ? sd->iov_max : ev_ptr->vsize;
      /* deliberate promotion from ssize_t to int64_t - matches ready */
      int64_t written =
        (int64_t)writev(fd, (const struct iovec *)ev_ptr->iov, iovcnt);

      if (0 > written) {
        return_socket_error_pid(sd, fd, errno, se->pid);
        erl_drv_mutex_unlock(se->socket.connected_socket.mutex);

        close(fd);

        SocketAction *sa1 = socket_action_alloc(SPB_ASYNC_DESTROY_SOCKET, fd,
                                                NULL, NULL, se->pid, sd);
        command_enqueue_and_notify(sa1, sd);

      } else if (written == ready) {
        for (int idx = 0; idx < ev_ptr->vsize; ++idx) {
          driver_free_binary(ev_ptr->binv[idx]);
        }
        driver_free(ev_ptr->iov);
        driver_free(ev_ptr->binv);
        ev_ptr->iov = NULL;
        ev_ptr->binv = NULL;
        ev_ptr->vsize = 0;
        se->socket.connected_socket.pending_writes = 0;
        erl_drv_mutex_unlock(se->socket.connected_socket.mutex);

      } else if (0 == written) {
        erl_drv_mutex_unlock(se->socket.connected_socket.mutex);


        SocketAction *sa1 = socket_action_alloc(SPB_ASYNC_INCOMPLETE_WRITE, fd,
                                                NULL, NULL, se->pid, sd);
        command_enqueue_and_notify(sa1, sd);

      } else {
        int64_t remaining = ready - written;
        int gone = 0;
        int64_t written2 = 0;
        for (int idx = 0; idx < ev_ptr->vsize; ++idx) {
          written2 = written - (int64_t)ev_ptr->iov[idx].iov_len;
          if (0 > written2) {
            /* the write stopped half way through an element */
            break;
          } else {
            written = written2;
            driver_free_binary(ev_ptr->binv[idx]);
            ++gone;
            if (0 == written)
              break;
          }
        }

        int vremaining = ev_ptr->vsize - gone;

        /* printf("ready: %d; gone: %d; offset: %d; vremaining: %d; remaining %d\r\n", */
        /*        ready, gone, written, vremaining, remaining); */

        if (0 < gone) {
          /* move the tail up to the front, then shrink */
          memmove(ev_ptr->iov, &(ev_ptr->iov[gone]),
                  vremaining * sizeof(SysIOVec));
          memmove(ev_ptr->binv, &(ev_ptr->binv[gone]),
                  vremaining * sizeof(ErlDrvBinary *));
          se->socket.connected_socket.pending_writes = remaining;
          ev_ptr->vsize = vremaining;

          ev_ptr->iov =
            driver_realloc(ev_ptr->iov, vremaining * sizeof(SysIOVec));
          if (NULL == ev_ptr->iov)
            driver_failure(sd->port, -1);

          ev_ptr->binv =
            driver_realloc(ev_ptr->binv, vremaining * sizeof(ErlDrvBinary *));
          if (NULL == ev_ptr->binv)
            driver_failure(sd->port, -1);
        }

        /* finally, patch up the first element of iov2 wrt written,
           which now holds the offset into the iov that we stopped
           in */
        ev_ptr->iov[0].iov_len  -= written;
        ev_ptr->iov[0].iov_base += written;

        /* printf("after:\r\n"); */
        /* dump_ev(ev_ptr); */

        erl_drv_mutex_unlock(se->socket.connected_socket.mutex);

        SocketAction *sa1 = socket_action_alloc(SPB_ASYNC_INCOMPLETE_WRITE, fd,
                                                NULL, NULL, se->pid, sd);
        command_enqueue_and_notify(sa1, sd);
      }
    }
  } else {
    erl_drv_mutex_unlock(sd->sockets_mutex);
  }
}

void socket_write(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  if (! read_int64(reader, &fd64_ptr)) {
    /* write is async so just drop this silently! */
    return;
  }
  /* we need to block the emulator thread until the libev thread has
     copied out the contents of the ErlIOVec ev. Thus we allocate on
     the stack, and use the mutex and cond. */

  SocketAction sa;
  socket_action_new(&sa, SPB_ASYNC_WRITE, (int)*fd64_ptr,
                    sd->cond, sd->command_mutex, sd->pid, sd);
  sa.ev = reader->ev;
  command_enqueue_and_notify(&sa, sd);
  await_done(&sa);
}


/***********************
 *  ev_loop callbacks  *
 ***********************/

static void spb_ev_socket_write_cb(EV_P_ ev_io *, int);
static void spb_ev_socket_read_cb(EV_P_ ev_io *, int);
static void spb_ev_listen_cb(EV_P_ ev_io *, int);

SocketEntry *socket_entry_alloc(const int fd, ErlDrvTermData pid,
                                SpbData *const sd) {
  SocketEntry *const se = (SocketEntry*)driver_alloc(sizeof(SocketEntry));
  if (NULL == se)
    driver_failure(sd->port, -1);

  se->serial = ++(sd->socket_entry_serial);
  se->fd = fd;
  se->pid = pid;

  se->watcher = (ev_io*)driver_alloc(sizeof(ev_io));
  if (NULL == se->watcher)
    driver_failure(sd->port, -1);

  return se;
}

SocketEntry *listen_socket_create(const int fd, ErlDrvTermData pid,
                                  SpbData *const sd) {
  SocketEntry *const se = socket_entry_alloc(fd, pid, sd);
  se->type = LISTEN_SOCKET;
  se->socket.listen_socket.acceptors = (Pvoid_t)NULL;
  ev_io_init(se->watcher, spb_ev_listen_cb, fd, EV_READ);
  se->watcher->data = sd;

  return se;
}

SocketEntry *connected_socket_create(const int fd, ErlDrvTermData pid,
                                     SpbData *const sd) {
  SocketEntry *const se = socket_entry_alloc(fd, pid, sd);
  se->type = CONNECTED_SOCKET;
  se->socket.connected_socket.quota = 0;
  se->socket.connected_socket.pending_writes = 0;
  se->socket.connected_socket.ev =
    (ErlIOVec *)driver_alloc(sizeof(ErlIOVec));
  if (NULL == se->socket.connected_socket.ev)
    driver_failure(sd->port, -1);
  se->socket.connected_socket.ev->vsize = 0;
  /* although size isn't even used as it's too small */
  se->socket.connected_socket.ev->size = 0;
  se->socket.connected_socket.ev->iov = NULL;
  se->socket.connected_socket.ev->binv = NULL;
  se->socket.connected_socket.mutex = erl_drv_mutex_create("spb socket mutex");
  if (NULL == se->socket.connected_socket.mutex)
    driver_failure(sd->port, -1);

  /* create the write watcher */
  se->socket.connected_socket.watcher = (ev_io*)driver_alloc(sizeof(ev_io));
  if (NULL == se->socket.connected_socket.watcher)
    driver_failure(sd->port, -1);

  ev_io_init(se->socket.connected_socket.watcher, spb_ev_socket_write_cb, fd,
             EV_WRITE);
  se->socket.connected_socket.watcher->data = sd;

  /* setup the read watcher (alloc'd in socket_entry_alloc) */
  ev_io_init(se->watcher, spb_ev_socket_read_cb, fd, EV_READ);
  se->watcher->data = sd;

  return se;
}

void free_binaries(const ErlIOVec *const ev) {
  for (int idx = 1; idx < ev->vsize; ++idx) {
    driver_free_binary(ev->binv[idx]);
  }
}

int socket_entry_destroy(SocketEntry *se, SpbData *const sd) {
  const int fd = se->fd;
  SocketEntry **se_ptr = NULL;

  erl_drv_mutex_lock(sd->sockets_mutex);
  JLG(se_ptr, sd->sockets, fd); /* find the SocketEntry for fd */
  /* we need to check that the se we've been passed really still
     exists in the sockets array */
  if (NULL != se_ptr && NULL != *se_ptr &&
      se->serial == (*se_ptr)->serial) {
    int rc = 0;
    Word_t freed = 0;
    /* looks like it all matches up. delete from sockets and then
       unlock */
    JLD(rc, sd->sockets, fd);

    ev_io_stop(sd->epoller, se->watcher);
    driver_free(se->watcher);

    switch (se->type) {

    case LISTEN_SOCKET:
      /* TODO - iterate through all acceptors and free them */
      erl_drv_mutex_unlock(sd->sockets_mutex);
      JLFA(freed, se->socket.listen_socket.acceptors);
      break;

    case CONNECTED_SOCKET:
      /* TODO - maybe warn if the write queue's not empty? */
      ev_io_stop(sd->epoller, se->socket.connected_socket.watcher);
      driver_free(se->socket.connected_socket.watcher);

      erl_drv_mutex_lock(se->socket.connected_socket.mutex);
      erl_drv_mutex_unlock(sd->sockets_mutex);
      free_binaries(se->socket.connected_socket.ev);
      driver_free(se->socket.connected_socket.ev->iov);
      driver_free(se->socket.connected_socket.ev->binv);
      driver_free(se->socket.connected_socket.ev);
      erl_drv_mutex_unlock(se->socket.connected_socket.mutex);
      erl_drv_mutex_destroy(se->socket.connected_socket.mutex);
      break;

    }
    driver_free(se);
    return TRUE;
  } else {
    erl_drv_mutex_unlock(sd->sockets_mutex);
    return FALSE;
  }
}

static void spb_ev_socket_write_cb(EV_P_ ev_io *w, int revents) {
  ev_io_stop(EV_A_ w); /* stop the watcher immediately */
  SpbData *const sd = (SpbData *const)(w->data);
  const int fd = w->fd;
  SocketEntry **se_ptr = NULL;
  SocketEntry *se = NULL;

  erl_drv_mutex_lock(sd->sockets_mutex);
  JLG(se_ptr, sd->sockets, fd); /* find the SocketEntry for fd */

  if (NULL != se_ptr && NULL != *se_ptr &&
      CONNECTED_SOCKET == (*se_ptr)->type) {
    se = *se_ptr;
    ErlIOVec *ev_ptr = NULL;
    erl_drv_mutex_lock(se->socket.connected_socket.mutex);
    erl_drv_mutex_unlock(sd->sockets_mutex);
    /* do we really have work to do? */
    ev_ptr = se->socket.connected_socket.ev;
    if (NULL != ev_ptr && se->socket.connected_socket.pending_writes > 0) {
      /* definitely have data to write, so call driver_async */
      erl_drv_mutex_unlock(se->socket.connected_socket.mutex);
      SocketAction *sa = socket_action_alloc(SPB_ASYNC_WRITE, fd,
                                              NULL, NULL, se->pid, sd);
      driver_async(sd->port, (unsigned int *)&(sa->fd),
                   (void (*)(void *))async_socket_write, sa, NULL);
    } else {
      erl_drv_mutex_unlock(se->socket.connected_socket.mutex);
    }
  }
}

static void spb_ev_socket_read_cb(EV_P_ ev_io *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  const int fd = w->fd;
  SocketEntry **se_ptr = NULL;
  SocketEntry *se = NULL;

  erl_drv_mutex_lock(sd->sockets_mutex);
  JLG(se_ptr, sd->sockets, fd); /* find the SocketEntry for fd */

  if (NULL != se_ptr && NULL != *se_ptr &&
      CONNECTED_SOCKET == (*se_ptr)->type) {
    se = *se_ptr;
    erl_drv_mutex_unlock(sd->sockets_mutex);
    ErlDrvTermData pid = se->pid;
    int bytes_ready_int = -1;

    if (ioctl(fd, FIONREAD, &bytes_ready_int) < 0) {
      return_socket_error_pid(sd, fd, errno, pid);
      return;
    }
    /* promote type to match with quota later on */
    int64_t bytes_ready = (int64_t)bytes_ready_int;

    if (0 == bytes_ready) {
      if (socket_entry_destroy(se, sd)) {
        if (0 > close(fd))
          return_socket_error_pid(sd, fd, errno, pid);
        else
          return_socket_closed_pid(sd, fd, pid);
      } else {
        /* someone else has already closed it. return closed */
        return_socket_closed_pid(sd, fd, pid);
      }

    } else {
      int64_t quota = se->socket.connected_socket.quota;
      int64_t requested = (0 <= quota && quota < bytes_ready) ? quota : bytes_ready;
      int64_t achieved = 0;

      ErlDrvBinary *binary = driver_alloc_binary(requested);
      if (NULL == binary)
        driver_failure(sd->port, -1);

      achieved = recv(fd, binary->orig_bytes, requested, 0);

      if (0 > achieved) {
        return_socket_error_pid(sd, fd, errno, pid);
        return;
      }

      if (achieved < requested) {
        binary = driver_realloc_binary(binary, achieved);
        if (NULL == binary)
          driver_failure(sd->port, -1);
      }

      sd->fd_data_spec[7] = fd;
      sd->fd_data_spec[9] = (ErlDrvTermData)binary;
      sd->fd_data_spec[10] = (ErlDrvUInt)achieved;
      driver_send_term(sd->port, pid, sd->fd_data_spec, FD_DATA_SPEC_LEN);
      sd->fd_data_spec[7] = 0;
      sd->fd_data_spec[9] = (ErlDrvTermData)NULL;
      sd->fd_data_spec[10] = (ErlDrvUInt)0;
      driver_free_binary(binary);

      if (0 < quota) {
        if (achieved == quota)
          ev_io_stop(EV_A_ w);
        se->socket.connected_socket.quota -= achieved;
      } else if (-1 == quota) {
        ev_io_stop(EV_A_ w);
        se->socket.connected_socket.quota = 0;
      }
    }
  } else {
    /* we've just received data for a socket we have no idea
       about. This is a fatal error */
    erl_drv_mutex_unlock(sd->sockets_mutex);
    perror("received data for unknown socket\r\n");
    driver_failure(sd->port, -1);
  }
}

static void spb_ev_listen_cb(EV_P_ ev_io *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  const int fd = w->fd;
  SocketEntry **se_ptr = NULL;
  SocketEntry *se = NULL;

  erl_drv_mutex_lock(sd->sockets_mutex);
  JLG(se_ptr, sd->sockets, fd); /* find the SocketEntry for fd */

  if (NULL != se_ptr && NULL != *se_ptr && LISTEN_SOCKET == (*se_ptr)->type) {
    se = *se_ptr;
    erl_drv_mutex_unlock(sd->sockets_mutex);
    ErlDrvTermData *const *pid_ptr = NULL;
    Word_t index = 0;

    /* find the first entry in acceptors */
    JLF(pid_ptr, se->socket.listen_socket.acceptors, index);

    if (NULL != pid_ptr && NULL != *pid_ptr) {
      const ErlDrvTermData pid = **pid_ptr; /* copy out pid */
      driver_free(*pid_ptr); /* was allocated in SPB_ASYNC_ACCEPT */

      int rc = 0; /* delete that entry from acceptors */
      JLD(rc, se->socket.listen_socket.acceptors, index);

      struct sockaddr_in client_addr;
      socklen_t client_len;

      client_len = sizeof(client_addr);
      memset(&client_addr, 0, client_len);
      const int accepted_fd =
        accept(fd, (struct sockaddr *)&client_addr, &client_len);

      if (0 > setnonblock(accepted_fd)) {
        perror("Cannot set socket non-blocking\r\n");
        driver_failure(sd->port, -1);
      }

      sd->ok_fd_spec[7] = accepted_fd;
      driver_send_term(sd->port, pid, sd->ok_fd_spec, OK_FD_SPEC_LEN);
      sd->ok_fd_spec[7] = 0;

      /* figure out if there are more pending acceptors */
      pid_ptr = NULL;
      JLF(pid_ptr, se->socket.listen_socket.acceptors, index);
      if (NULL == pid_ptr)
        ev_io_stop(EV_A_ w);

      erl_drv_mutex_lock(sd->sockets_mutex);
      se_ptr = NULL;
      JLI(se_ptr, sd->sockets, accepted_fd);
      *se_ptr = connected_socket_create(accepted_fd, pid, sd);
      erl_drv_mutex_unlock(sd->sockets_mutex);

    } else {
      perror("Accepted a connection, but no acceptor ready\r\n");
      driver_failure(sd->port, -1);
    }
  } else {
    erl_drv_mutex_unlock(sd->sockets_mutex);
    perror("Cannot find entry for listening socket\r\n");
    driver_failure(sd->port, -1);
  }
}

static void spb_ev_async_cb(EV_P_ ev_async *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  SocketAction *sa = NULL;
  command_dequeue(&sa, sd);
  while (NULL != sa) {
   switch (sa->type) {

    case SPB_ASYNC_START:
      mark_done_and_signal(sa);
      driver_send_term(sd->port, sa->pid, sd->ok_atom_spec, ATOM_SPEC_LEN);
      break;

    case SPB_ASYNC_EXIT:
      mark_done_and_signal(sa);
      ev_async_stop(EV_A_ w);
      ev_unloop(EV_A_ EVUNLOOP_ALL);
      ev_loop_destroy(EV_A);
      break;

    case SPB_ASYNC_LISTEN:
      {
        /* The main driver thread has done the open, so if we've got
           this far, we know the socket was opened successfully */
        const int fd = sa->fd;
        const ErlDrvTermData pid = sa->pid;
        mark_done_and_signal(sa);
        erl_drv_mutex_lock(sd->sockets_mutex);
        SocketEntry **se_ptr = NULL;
        JLI(se_ptr, sd->sockets, fd);
        *se_ptr = listen_socket_create(fd, pid, sd);
        erl_drv_mutex_unlock(sd->sockets_mutex);

        return_ok_fd_pid(sd, pid, fd);
        break;
      }

    case SPB_ASYNC_CLOSE:
      {
        /* Note the same close code is used for listening and connected
           sockets */
        const int fd = sa->fd;
        const ErlDrvTermData pid = sa->pid;
        mark_done_and_signal(sa);
        erl_drv_mutex_lock(sd->sockets_mutex);
        SocketEntry **se_ptr = NULL;
        SocketEntry *se = NULL;
        JLG(se_ptr, sd->sockets, fd);
        if (NULL != se_ptr && NULL != *se_ptr && pid == (*se_ptr)->pid) {
          /* destroy first to ensure no async writer is working on the
             fd when we do the */
          se = *se_ptr;
          erl_drv_mutex_unlock(sd->sockets_mutex);

          if (socket_entry_destroy(se, sd)) {
            if (0 > close(fd))
              return_socket_error_pid(sd, fd, errno, se->pid);
            else
              return_socket_closed_pid(sd, fd, pid);
          } else {
            /* someone else has already closed it. return closed */
            return_socket_closed_pid(sd, fd, pid);
          }

        } else {
          erl_drv_mutex_unlock(sd->sockets_mutex);
          return_socket_bad_pid(sd, fd, pid); /* programmer messed up */
        }
        break;
      }

    case SPB_ASYNC_ACCEPT:
      {
        const int fd = sa->fd;
        const ErlDrvTermData pid = sa->pid;
        /* release the emulator thread - we've copied out everything
           we need */
        mark_done_and_signal(sa);
        erl_drv_mutex_lock(sd->sockets_mutex);
        SocketEntry **se_ptr = NULL;
        SocketEntry *se = NULL;
        JLG(se_ptr, sd->sockets, fd);
        if (NULL != se_ptr && NULL != *se_ptr &&
            LISTEN_SOCKET == (*se_ptr)->type) {
          se = *se_ptr;
          erl_drv_mutex_unlock(sd->sockets_mutex);
          Word_t index = -1;
          ErlDrvTermData **pid_ptr_found = NULL;
          /* find the last present index in the list of acceptors */
          JLL(pid_ptr_found, se->socket.listen_socket.acceptors, index);
          if (NULL == pid_ptr_found)
            index = 0;
          else
            ++index;

          ErlDrvTermData *pid_ptr =
            (ErlDrvTermData *)driver_alloc(sizeof(ErlDrvTermData));
          if (NULL == pid_ptr)
            driver_failure(sd->port, -1);
          *pid_ptr = pid;  /* copy the calling pid into the memory
                              just allocated */

          ErlDrvTermData **pid_ptr_ptr = NULL;
          JLI(pid_ptr_ptr, se->socket.listen_socket.acceptors, index);
          *pid_ptr_ptr = pid_ptr; /* make the array entry point at the
                                     memory allocated */

          if (0 == index) /* if we're the first acceptor, enable the
                             watcher */
            ev_io_start(sd->epoller, se->watcher);
          return_ok_fd_pid(sd, pid, fd);

        } else {
          erl_drv_mutex_unlock(sd->sockets_mutex);
          return_socket_bad_pid(sd, fd, pid); /* programmer messed up */
        }
        break;
      }

    case SPB_ASYNC_RECV:
      {
        const int fd = sa->fd;
        const int64_t new_quota = sa->value;
        const ErlDrvTermData pid = sa->pid;
        /* release the emulator thread - we've copied out everything we
           need */
        mark_done_and_signal(sa);
        erl_drv_mutex_lock(sd->sockets_mutex);
        SocketEntry **se_ptr = NULL;
        SocketEntry *se = NULL;
        JLG(se_ptr, sd->sockets, fd);
        if (NULL != se_ptr && NULL != *se_ptr &&
            CONNECTED_SOCKET == (*se_ptr)->type && pid == (*se_ptr)->pid) {
          se = *se_ptr;
          erl_drv_mutex_unlock(sd->sockets_mutex);
          int64_t old_quota = se->socket.connected_socket.quota;
          se->socket.connected_socket.quota = new_quota;
          if (0 == new_quota && 0 != old_quota)
            ev_io_stop(sd->epoller, se->watcher);
          else if (0 != new_quota && 0 == old_quota) {
            ev_io_start(sd->epoller, se->watcher);
          }
        } else {
          erl_drv_mutex_unlock(sd->sockets_mutex);
          return_socket_bad_pid(sd, fd, pid); /* programmer messed up */
        }
        break;
      }

    case SPB_ASYNC_WRITE:
      {
        /* need to copy out and extend the writer's ev before we can
           release the driver */
        erl_drv_mutex_lock(sd->sockets_mutex);
        SocketEntry **se_ptr = NULL;
        SocketEntry *se = NULL;
        JLG(se_ptr, sd->sockets, sa->fd);
        if (NULL != se_ptr && NULL != *se_ptr &&
            CONNECTED_SOCKET == (*se_ptr)->type) {
          se = *se_ptr;
          erl_drv_mutex_lock(se->socket.connected_socket.mutex);
          erl_drv_mutex_unlock(sd->sockets_mutex);
          ErlIOVec *ev_ptr = se->socket.connected_socket.ev;

          int new_offset = 1;
          if (sa->ev->iov[1].iov_len == WRITE_COMMAND_PREFIX_LENGTH) {
            /* row 1 is prefix only. Skip it */
            new_offset = 2;
          } else {
            /* adjust row 1 to skip prefix */
            sa->ev->iov[1].iov_len -= WRITE_COMMAND_PREFIX_LENGTH;
            sa->ev->iov[1].iov_base += WRITE_COMMAND_PREFIX_LENGTH;
          }
          int length = sa->ev->vsize - new_offset;
          int total_length = length + ev_ptr->vsize;

          ev_ptr->iov = driver_realloc(ev_ptr->iov,
                                       total_length * sizeof(SysIOVec));
          if (NULL == ev_ptr->iov)
            driver_failure(sd->port, -1);

          ev_ptr->binv = driver_realloc(ev_ptr->binv,
                                        total_length * sizeof(ErlDrvBinary *));
          if (NULL == ev_ptr->binv)
            driver_failure(sd->port, -1);

          int old_offset = ev_ptr->vsize;
          for (int idx = 0; idx + new_offset < sa->ev->vsize; ++idx) {
            driver_binary_inc_refc(sa->ev->binv[new_offset + idx]);
            ev_ptr->iov[old_offset + idx] = sa->ev->iov[new_offset + idx];
            ev_ptr->binv[old_offset + idx] = sa->ev->binv[new_offset + idx];
            /* we use size to mean writable size */
            se->socket.connected_socket.pending_writes +=
              (int64_t)sa->ev->iov[new_offset + idx].iov_len;
          }
          ev_ptr->vsize = total_length;

          erl_drv_mutex_unlock(se->socket.connected_socket.mutex);

          if (0 == old_offset) {
            SocketAction *sa1 = socket_action_alloc(SPB_ASYNC_WRITE, sa->fd,
                                                    NULL, NULL, sa->pid, sd);
            mark_done_and_signal(sa);
            driver_async(sd->port, (unsigned int *)&(sa1->fd),
                         (void (*)(void *))async_socket_write, sa1, NULL);
          } else {
            mark_done_and_signal(sa);
          }
        } else {
          erl_drv_mutex_unlock(sd->sockets_mutex);
          mark_done_and_signal(sa);
        }
        break;
      }

    case SPB_ASYNC_INCOMPLETE_WRITE:
      {
        const int fd = sa->fd;
        mark_done_and_signal(sa);
        erl_drv_mutex_lock(sd->sockets_mutex);
        SocketEntry **se_ptr = NULL;
        JLG(se_ptr, sd->sockets, fd);
        if (NULL != se_ptr && NULL != *se_ptr &&
            CONNECTED_SOCKET == (*se_ptr)->type)
          ev_io_start(sd->epoller, (*se_ptr)->socket.connected_socket.watcher);
        erl_drv_mutex_unlock(sd->sockets_mutex);
        break;
      }

    case SPB_ASYNC_DESTROY_SOCKET:
      {
        const int fd = sa->fd;
        const ErlDrvTermData pid = sa->pid;
        mark_done_and_signal(sa);
        erl_drv_mutex_lock(sd->sockets_mutex);
        SocketEntry **se_ptr = NULL;
        SocketEntry *se = NULL;
        JLG(se_ptr, sd->sockets, fd);
        if (NULL != se_ptr && NULL != *se_ptr && pid == (*se_ptr)->pid) {
          /* destroy first to ensure no async writer is working on the
             fd when we do the */
          se = *se_ptr;
          erl_drv_mutex_unlock(sd->sockets_mutex);
          /* don't care if this succeeds or not */
          socket_entry_destroy(se, sd);
        } else {
          erl_drv_mutex_unlock(sd->sockets_mutex);
        }
        break;
      }
    }

    command_dequeue(&sa, sd);
  }
}


/********************************
 *  ev_loop thread entry point  *
 ********************************/

static void *spb_ev_start(void *arg) {
  SpbData *const sd = (SpbData*)arg;

  erl_drv_mutex_lock(sd->command_mutex);

  sd->epoller = ev_loop_new(0);
  if (NULL == sd->epoller)
    driver_failure(sd->port, -1);

  sd->async_watcher = (ev_async*)driver_alloc(sizeof(ev_async));
  if (NULL == sd->async_watcher)
    driver_failure(sd->port, -1);

  ev_async_init(sd->async_watcher, &spb_ev_async_cb);
  sd->async_watcher->data = sd;
  ev_async_start(sd->epoller, sd->async_watcher);

  erl_drv_cond_signal(sd->cond);
  erl_drv_mutex_unlock(sd->command_mutex);

  ev_loop(sd->epoller, 0);
  return NULL;
}


/*****************************
 *  Erlang Driver Callbacks  *
 *****************************/

static int spb_init() {
  ErlDrvSysInfo info;
  driver_system_info(&info, sizeof(ErlDrvSysInfo));

  if (0 == info.thread_support) {
    perror("spb cannot load: spb requires thread support\r\n");
    return -1;
  }

  if (0 == info.smp_support) {
    perror("spb cannot load: spb requires SMP support\r\n");
    return -1;
  }

  if (0 == info.async_threads) {
    perror("spb cannot load: spb requires async threads\r\n");
    return -1;
  }

  return 0;
}

static ErlDrvData spb_start(const ErlDrvPort port, char *const buff) {
  SpbData *const sd = (SpbData*)driver_alloc(sizeof(SpbData));

  if (NULL == sd)
    return ERL_DRV_ERROR_GENERAL;

  sd->port = port;
  sd->pid = driver_caller(port);

  sd->no_such_command_atom_spec =
    (ErlDrvTermData*)driver_alloc(ATOM_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->no_such_command_atom_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->no_such_command_atom_spec[0] = ERL_DRV_ATOM;
  sd->no_such_command_atom_spec[1] = driver_mk_atom("spb_event");
  sd->no_such_command_atom_spec[2] = ERL_DRV_PORT;
  sd->no_such_command_atom_spec[3] = driver_mk_port(port);
  sd->no_such_command_atom_spec[4] = ERL_DRV_ATOM;
  sd->no_such_command_atom_spec[5] = driver_mk_atom("no_such_command");
  sd->no_such_command_atom_spec[6] = ERL_DRV_TUPLE;
  sd->no_such_command_atom_spec[7] = 3;

  sd->ok_atom_spec =
    (ErlDrvTermData*)driver_alloc(ATOM_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->ok_atom_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->ok_atom_spec[0] = ERL_DRV_ATOM;
  sd->ok_atom_spec[1] = driver_mk_atom("spb_event");
  sd->ok_atom_spec[2] = ERL_DRV_PORT;
  sd->ok_atom_spec[3] = driver_mk_port(port);
  sd->ok_atom_spec[4] = ERL_DRV_ATOM;
  sd->ok_atom_spec[5] = driver_mk_atom("ok");
  sd->ok_atom_spec[6] = ERL_DRV_TUPLE;
  sd->ok_atom_spec[7] = 3;

  sd->reader_error_spec = (ErlDrvTermData*)
    driver_alloc(READER_ERROR_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->reader_error_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->reader_error_spec[0] = ERL_DRV_ATOM;
  sd->reader_error_spec[1] = driver_mk_atom("spb_event");
  sd->reader_error_spec[2] = ERL_DRV_PORT;
  sd->reader_error_spec[3] = driver_mk_port(port);
  sd->reader_error_spec[4] = ERL_DRV_ATOM;
  sd->reader_error_spec[5] = driver_mk_atom("reader_error");
  sd->reader_error_spec[6] = ERL_DRV_STRING;
  sd->reader_error_spec[7] = (ErlDrvTermData)NULL;
  sd->reader_error_spec[8] = 0;
  sd->reader_error_spec[9] = ERL_DRV_TUPLE;
  sd->reader_error_spec[10] = 2;
  sd->reader_error_spec[11] = ERL_DRV_TUPLE;
  sd->reader_error_spec[12] = 3;

  sd->socket_error_spec = (ErlDrvTermData*)
    driver_alloc(SOCKET_ERROR_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->socket_error_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->socket_error_spec[0] = ERL_DRV_ATOM;
  sd->socket_error_spec[1] = driver_mk_atom("spb_event");
  sd->socket_error_spec[2] = ERL_DRV_PORT;
  sd->socket_error_spec[3] = driver_mk_port(port);
  sd->socket_error_spec[4] = ERL_DRV_ATOM;
  sd->socket_error_spec[5] = driver_mk_atom("socket_error");
  sd->socket_error_spec[6] = ERL_DRV_INT;
  sd->socket_error_spec[7] = (ErlDrvSInt)0;
  sd->socket_error_spec[8] = ERL_DRV_STRING;
  sd->socket_error_spec[9] = (ErlDrvTermData)NULL;
  sd->socket_error_spec[10] = 0;
  sd->socket_error_spec[11] = ERL_DRV_TUPLE;
  sd->socket_error_spec[12] = 3;
  sd->socket_error_spec[13] = ERL_DRV_TUPLE;
  sd->socket_error_spec[14] = 3;

  sd->ok_fd_spec = (ErlDrvTermData*)
    driver_alloc(OK_FD_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->ok_fd_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->ok_fd_spec[0] = ERL_DRV_ATOM;
  sd->ok_fd_spec[1] = driver_mk_atom("spb_event");
  sd->ok_fd_spec[2] = ERL_DRV_PORT;
  sd->ok_fd_spec[3] = driver_mk_port(port);
  sd->ok_fd_spec[4] = ERL_DRV_ATOM;
  sd->ok_fd_spec[5] = driver_mk_atom("ok");
  sd->ok_fd_spec[6] = ERL_DRV_INT;
  sd->ok_fd_spec[7] = (ErlDrvSInt)0;
  sd->ok_fd_spec[8] = ERL_DRV_TUPLE;
  sd->ok_fd_spec[9] = 2;
  sd->ok_fd_spec[10] = ERL_DRV_TUPLE;
  sd->ok_fd_spec[11] = 3;

  sd->fd_data_spec = (ErlDrvTermData*)
    driver_alloc(FD_DATA_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->fd_data_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->fd_data_spec[0] = ERL_DRV_ATOM;
  sd->fd_data_spec[1] = driver_mk_atom("spb_event");
  sd->fd_data_spec[2] = ERL_DRV_PORT;
  sd->fd_data_spec[3] = driver_mk_port(port);
  sd->fd_data_spec[4] = ERL_DRV_ATOM;
  sd->fd_data_spec[5] = driver_mk_atom("data");
  sd->fd_data_spec[6] = ERL_DRV_INT;
  sd->fd_data_spec[7] = (ErlDrvSInt)0;
  sd->fd_data_spec[8] = ERL_DRV_BINARY;
  sd->fd_data_spec[9] = (ErlDrvTermData)NULL;
  sd->fd_data_spec[10] = (ErlDrvUInt)0;
  sd->fd_data_spec[11] = (ErlDrvUInt)0;
  sd->fd_data_spec[12] = ERL_DRV_TUPLE;
  sd->fd_data_spec[13] = 3;
  sd->fd_data_spec[14] = ERL_DRV_TUPLE;
  sd->fd_data_spec[15] = 3;

  sd->fd_closed_spec = (ErlDrvTermData*)
    driver_alloc(FD_CLOSED_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->fd_closed_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->fd_closed_spec[0] = ERL_DRV_ATOM;
  sd->fd_closed_spec[1] = driver_mk_atom("spb_event");
  sd->fd_closed_spec[2] = ERL_DRV_PORT;
  sd->fd_closed_spec[3] = driver_mk_port(port);
  sd->fd_closed_spec[4] = ERL_DRV_ATOM;
  sd->fd_closed_spec[5] = driver_mk_atom("closed");
  sd->fd_closed_spec[6] = ERL_DRV_INT;
  sd->fd_closed_spec[7] = (ErlDrvSInt)0;
  sd->fd_closed_spec[8] = ERL_DRV_TUPLE;
  sd->fd_closed_spec[9] = 2;
  sd->fd_closed_spec[10] = ERL_DRV_TUPLE;
  sd->fd_closed_spec[11] = 3;

  sd->fd_bad_spec = (ErlDrvTermData*)
    driver_alloc(FD_BAD_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->fd_bad_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->fd_bad_spec[0] = ERL_DRV_ATOM;
  sd->fd_bad_spec[1] = driver_mk_atom("spb_event");
  sd->fd_bad_spec[2] = ERL_DRV_PORT;
  sd->fd_bad_spec[3] = driver_mk_port(port);
  sd->fd_bad_spec[4] = ERL_DRV_ATOM;
  sd->fd_bad_spec[5] = driver_mk_atom("badarg");
  sd->fd_bad_spec[6] = ERL_DRV_INT;
  sd->fd_bad_spec[7] = (ErlDrvSInt)0;
  sd->fd_bad_spec[8] = ERL_DRV_TUPLE;
  sd->fd_bad_spec[9] = 2;
  sd->fd_bad_spec[10] = ERL_DRV_TUPLE;
  sd->fd_bad_spec[11] = 3;

  /* Note that startup here is a bit surprising: we don't want to
     create the epoller in this thread because if we do then we'll
     have to invoke ev_loop_fork in the child, which will cause the
     loop to throw away anything pending, until it hits the loop
     proper. If we did that, then there's a race with us sending
     anything subsequent to it: we might send to it before it hits the
     loop proper post the ev_loop_fork and thus lose our message.

     Consequently, we allow the child to create the epoller, we wait
     for it and then we signal it, at which point it finally sends an
     'ok' reply all the way out to the erlang port owner process. At
     that point, everything truly is up and running.
  */
  sd->epoller = NULL;
  sd->command_mutex = erl_drv_mutex_create("spb command mutex");
  if (NULL == sd->command_mutex)
    return ERL_DRV_ERROR_GENERAL;
  sd->command_queue = (Pvoid_t)NULL;

  sd->cond = erl_drv_cond_create("spb command condition");
  if (NULL == sd->cond)
    return ERL_DRV_ERROR_GENERAL;

  sd->sockets = (Pvoid_t)NULL;
  sd->sockets_mutex = erl_drv_mutex_create("spb sockets mutex");
  if (NULL == sd->sockets_mutex)
    return ERL_DRV_ERROR_GENERAL;

  sd->iov_max = 0;
#if defined(_SC_IOV_MAX) /* IRIX, MacOS X, FreeBSD, Solaris, QNX, ... */
  sd->iov_max = sysconf(_SC_IOV_MAX);
#elif defined(IOV_MAX)
  sd->iov_max = IOV_MAX;
#endif
  sd->iov_max = sd->iov_max <= 0 ? DEFAULT_IOV_MAX : sd->iov_max;

  sd->socket_entry_serial = 0;

  if (0 != erl_drv_thread_create("spb", &(sd->tid), &spb_ev_start, sd, NULL))
    return ERL_DRV_ERROR_GENERAL;

  await_epoller(sd);
  SocketAction *sa = socket_action_alloc(SPB_ASYNC_START, 0, NULL, NULL,
                                         sd->pid, sd);
  command_enqueue_and_notify(sa, sd);

  return (ErlDrvData)sd;
}

static void spb_stop(const ErlDrvData drv_data) {
  SpbData *const sd = (SpbData*)drv_data;

  SocketAction *sa = socket_action_alloc(SPB_ASYNC_EXIT, 0, NULL, NULL,
                                         sd->pid, sd);
  command_enqueue_and_notify(sa, sd);
  erl_drv_thread_join(sd->tid, NULL);

  driver_free((char*)sd->no_such_command_atom_spec);
  driver_free((char*)sd->ok_atom_spec);
  driver_free((char*)sd->reader_error_spec);
  driver_free((char*)sd->socket_error_spec);
  driver_free((char*)sd->ok_fd_spec);
  driver_free((char*)sd->fd_data_spec);
  driver_free((char*)sd->fd_closed_spec);
  driver_free((char*)sd->fd_bad_spec);
  driver_free((char*)sd->async_watcher);

  erl_drv_mutex_destroy(sd->command_mutex);
  erl_drv_cond_destroy(sd->cond);

  erl_drv_mutex_destroy(sd->sockets_mutex);
  Word_t freed = 0;
  JLFA(freed, sd->sockets);
  JLFA(freed, sd->command_queue);

  driver_free((char*)drv_data);
}

static void spb_outputv(ErlDrvData drv_data, ErlIOVec *const ev) {
  SpbData *const sd = (SpbData*)drv_data;
  sd->pid = driver_caller(sd->port);
  const uint8_t* command = &spb_invalid_command;
  Reader reader;
  make_reader(ev, &reader);
  ErlDrvTermData* spec = NULL;
  /* dump_ev(ev); */
  if (read_uint8(&reader, &command)) {
    switch (*command) {

    case SPB_LISTEN:
      socket_listen(sd, &reader);
      break;

    case SPB_CLOSE:
      socket_close(sd, &reader);
      break;

    case SPB_ACCEPT:
      socket_accept(sd, &reader);
      break;

    case SPB_RECV:
      socket_recv(sd, &reader);
      break;

    case SPB_WRITE:
      socket_write(sd, &reader);
      break;

    default:
      spec = sd->no_such_command_atom_spec;
    }
  } else {
    return_reader_error(sd, &reader);
  }

  if (NULL != spec) {
    driver_send_term(sd->port, sd->pid, spec, ATOM_SPEC_LEN);
  }

}

static ErlDrvEntry spb_driver_entry =
{
  .init = spb_init,
  .start = spb_start,
  .stop = spb_stop,
  .driver_name = (char*) "libspb",
  .outputv = spb_outputv,
  .extended_marker = ERL_DRV_EXTENDED_MARKER,
  .major_version = ERL_DRV_EXTENDED_MAJOR_VERSION,
  .minor_version = ERL_DRV_EXTENDED_MINOR_VERSION,
  .driver_flags = ERL_DRV_FLAG_USE_PORT_LOCKING
};

DRIVER_INIT (libspb);

DRIVER_INIT (libspb) /* must match name in driver_entry */
{
  return &spb_driver_entry;
}
