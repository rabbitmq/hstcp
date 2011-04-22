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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

typedef struct {
  uint8_t type;
  const void *data;
} Command;

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
  ErlDrvMutex    *mutex;             /* mutex for safely communicating with our thread */
  Command        command;            /* the command being sent to our thread           */
  Pvoid_t        sockets;            /* the Judy array to store state of FDs in        */
  ErlDrvCond     *cond;              /* conditional for signalling from thread to drv  */
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
} SocketEntry;

typedef struct {
  int fd;
  int64_t value;
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
  printf("done\r\n");
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
  erl_drv_mutex_lock(sd->mutex);
  while (NULL != ptr && NULL == *ptr)
    erl_drv_cond_wait(sd->cond, sd->mutex);
  erl_drv_mutex_unlock(sd->mutex);
}

void await_null(const void *const *const ptr, SpbData *const sd) {
  erl_drv_mutex_lock(sd->mutex);
  while (NULL != ptr && NULL != *ptr)
    erl_drv_cond_wait(sd->cond, sd->mutex);
  erl_drv_mutex_unlock(sd->mutex);
}

void await_epoller(SpbData *const sd) {
  await_non_null((const void const* const*)&(sd->epoller), sd);
}

void set_null_and_signal(const void **const ptr, SpbData *const sd) {
  erl_drv_mutex_lock(sd->mutex);
  *ptr = NULL;
  erl_drv_cond_signal(sd->cond);
  erl_drv_mutex_unlock(sd->mutex);
}


/*****************************
 *  Command Queue Functions  *
 *****************************/

void command_set_and_notify(const uint8_t type, const void *const data,
                            SpbData *const sd) {
  erl_drv_mutex_lock(sd->mutex);
  sd->command.type = type;
  sd->command.data = data;
  erl_drv_mutex_unlock(sd->mutex);
  ev_async_send(sd->epoller, sd->async_watcher);
}

void command_get(Command *cmd, SpbData *const sd) {
  erl_drv_mutex_lock(sd->mutex);
  *cmd = sd->command; /* copy out the command from sd */
  erl_drv_mutex_unlock(sd->mutex);
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

void return_socket_error(SpbData *const sd, const int fd, const int error) {
  return_socket_error_str_pid(sd, fd, strerror(error), sd->pid);
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
    return_socket_error(sd, 0, errno);
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
    return_socket_error(sd, 0, errno);
    return;
  }

  if (0 > bind(listen_fd,
               (struct sockaddr *)&listen_address,
               sizeof(listen_address))) {
    return_socket_error(sd, 0, errno);
    return;
  }

  /* listen for incoming connections. set backlog to 128 */
  if (0 > listen(listen_fd, 128)) {
    return_socket_error(sd, 0, errno);
    return;
  }

  const int reuse = 1;
  /* turn on reuseaddr */
  if (0 > setsockopt(listen_fd,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &reuse,
                     sizeof(reuse))) {
    return_socket_error(sd, 0, errno);
    return;
  }

  /* put socket into nonblocking mode - needed for libev */
  if (0 > setnonblock(listen_fd)) {
    return_socket_error(sd, 0, errno);
    return;
  }

  const int *listen_fd_ptr = &listen_fd;
  const void **const listen_fd_ptr_ptr = (const void **const)&listen_fd_ptr;
  command_set_and_notify(SPB_ASYNC_LISTEN, listen_fd_ptr_ptr, sd);
  await_null(listen_fd_ptr_ptr, sd);
}

void socket_close(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  if (! read_int64(reader, &fd64_ptr)) {
    return_reader_error(sd, reader);
    return;
  }
  const int fd = (int)*fd64_ptr;
  const int *const fd_ptr = &fd;
  const void **const fd_ptr_ptr = (const void **const)&fd_ptr;
  command_set_and_notify(SPB_ASYNC_CLOSE, fd_ptr_ptr, sd);
  await_null(fd_ptr_ptr, sd);
}

void socket_accept(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  if (! read_int64(reader, &fd64_ptr)) {
    return_reader_error(sd, reader);
    return;
  }
  const int fd = (int)*fd64_ptr;
  const int *const fd_ptr = &fd;
  const void **const fd_ptr_ptr = (const void **const)&fd_ptr;
  command_set_and_notify(SPB_ASYNC_ACCEPT, fd_ptr_ptr, sd);
  await_null(fd_ptr_ptr, sd);
}

void socket_recv(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  const int64_t *bytes_ptr = NULL;
  if (! (read_int64(reader, &fd64_ptr) && read_int64(reader, &bytes_ptr))) {
    return_reader_error(sd, reader);
    return;
  }
  SocketAction sa;
  sa.fd = (int)*fd64_ptr;
  sa.value = *bytes_ptr;
  const SocketAction *sa_ptr = &sa;
  const void **sa_ptr_ptr = (const void **)&sa_ptr;
  command_set_and_notify(SPB_ASYNC_RECV, sa_ptr_ptr, sd);
  await_null(sa_ptr_ptr, sd);
}


/***********************
 *  ev_loop callbacks  *
 ***********************/

static void spb_ev_socket_read_cb(EV_P_ ev_io *, int);
static void spb_ev_listen_cb(EV_P_ ev_io *, int);

SocketEntry *listen_socket_create(const int fd, ErlDrvTermData pid,
                                  SpbData *const sd) {
  SocketEntry *const se = (SocketEntry*)driver_alloc(sizeof(SocketEntry));
  if (NULL == se)
    driver_failure(sd->port, -1);

  se->type = LISTEN_SOCKET;
  se->fd = fd;
  se->pid = pid;
  se->socket.listen_socket.acceptors = (Pvoid_t)NULL;

  se->watcher = (ev_io*)driver_alloc(sizeof(ev_io));
  if (NULL == se->watcher)
    driver_failure(sd->port, -1);

  ev_io_init(se->watcher, spb_ev_listen_cb, fd, EV_READ);
  se->watcher->data = sd;

  return se;
}

SocketEntry *connected_socket_create(const int fd, ErlDrvTermData pid,
                                     SpbData *const sd) {
  SocketEntry *const se = (SocketEntry*)driver_alloc(sizeof(SocketEntry));
  if (NULL == se)
    driver_failure(sd->port, -1);

  se->type = CONNECTED_SOCKET;
  se->fd = fd;
  se->pid = pid;
  se->socket.connected_socket.quota = 0;

  se->watcher = (ev_io*)driver_alloc(sizeof(ev_io));
  if (NULL == se->watcher)
    driver_failure(sd->port, -1);

  ev_io_init(se->watcher, spb_ev_socket_read_cb, fd, EV_READ);
  se->watcher->data = sd;

  return se;
}

void socket_entry_destroy(SocketEntry *se, SpbData *const sd) {
  Word_t freed = 0; /* don't actually care about how many bytes judy frees up */
  ev_io_stop(sd->epoller, se->watcher);
  driver_free(se->watcher);

  switch (se->type) {

  case LISTEN_SOCKET:
    /* TODO - iterate through all acceptors and free them */
    JLFA(freed, se->socket.listen_socket.acceptors);
    break;

  case CONNECTED_SOCKET:
    break;

  }

  driver_free(se);
}

static void spb_ev_socket_read_cb(EV_P_ ev_io *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  const int fd = w->fd;
  SocketEntry **se = NULL;

  JLG(se, sd->sockets, w->fd); /* find the SocketEntry for fd */

  if (NULL != se && NULL != *se && CONNECTED_SOCKET == (*se)->type) {
    ErlDrvTermData pid = (*se)->pid;
    int bytes_ready = -1;

    if (ioctl(fd, FIONREAD, &bytes_ready) < 0) {
      return_socket_error_pid(sd, fd, errno, pid);
      return;
    }

    if (0 == bytes_ready) {
      ev_io_stop(EV_A_ w);
      if (0 > close(fd))
        return_socket_error_pid(sd, fd, errno, pid);
      else
        return_socket_closed_pid(sd, fd, pid);
      socket_entry_destroy(*se, sd);
      int rc; /* don't care about the result of the judy delete */
      JLD(rc, sd->sockets, fd);

    } else {
      int quota = (*se)->socket.connected_socket.quota;
      int requested = (0 <= quota && quota < bytes_ready) ? quota : bytes_ready;
      ssize_t achieved = 0;

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
        (*se)->socket.connected_socket.quota -= achieved;
      } else if (-1 == quota) {
        ev_io_stop(EV_A_ w);
        (*se)->socket.connected_socket.quota = 0;
      }
    }
  } else {
    /* we've just received data for a socket we have no idea
       about. This is a fatal error */
    perror("received data for unknown socket\r\n");
    driver_failure(sd->port, -1);
  }
}

static void spb_ev_listen_cb(EV_P_ ev_io *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  const int fd = w->fd;
  SocketEntry **se = NULL;

  JLG(se, sd->sockets, fd); /* find the SocketEntry for fd */

  if (NULL != se && NULL != *se && LISTEN_SOCKET == (*se)->type) {
    ErlDrvTermData *const *pid_ptr = NULL;
    Word_t index = 0;

    /* find first entry in acceptors */
    JLBC(pid_ptr, (*se)->socket.listen_socket.acceptors, 1, index);

    if (NULL != pid_ptr && NULL != *pid_ptr) {
      const ErlDrvTermData pid = **pid_ptr; /* copy out pid */
      driver_free(*pid_ptr); /* was allocated in SPB_ASYNC_ACCEPT */

      int rc = 0; /* delete that entry from acceptors */
      JLD(rc, (*se)->socket.listen_socket.acceptors, index);

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
      JLBC(pid_ptr, (*se)->socket.listen_socket.acceptors, 1, index);
      if (NULL == pid_ptr)
        ev_io_stop(EV_A_ w);

      se = NULL;
      JLI(se, sd->sockets, accepted_fd);
      *se = connected_socket_create(accepted_fd, pid, sd);

    } else {
      perror("Accepted a connection, but no acceptor ready\r\n");
      driver_failure(sd->port, -1);
    }
  } else {
    perror("Cannot find entry for listening socket\r\n");
    driver_failure(sd->port, -1);
  }
}

static void spb_ev_async_cb(EV_P_ ev_async *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  ErlDrvTermData caller = sd->pid;
  Command command;
  command_get(&command, sd);
  switch (command.type) {

  case SPB_ASYNC_START:
    driver_send_term(sd->port, caller, sd->ok_atom_spec, ATOM_SPEC_LEN);
    break;

  case SPB_ASYNC_EXIT:
    ev_async_stop(EV_A_ w);
    ev_unloop(EV_A_ EVUNLOOP_ALL);
    ev_loop_destroy(EV_A);
    break;

  case SPB_ASYNC_LISTEN:
    {
      /* The main driver thread has done the open, so if we've got
         this far, we know the socket was opened successfully */
      const int **const fd_ptr = (const int **const)command.data;
      const int fd = **fd_ptr;
      set_null_and_signal((const void **const)fd_ptr, sd);
      SocketEntry **se = NULL;
      JLI(se, sd->sockets, fd);
      *se = listen_socket_create(fd, caller, sd);

      return_ok_fd_pid(sd, caller, fd);
      break;
    }

  case SPB_ASYNC_CLOSE:
    {
      /* Note the same close code is used for listening and connected
         sockets */
      const int **const fd_ptr = (const int **const)command.data;
      const int fd = **fd_ptr;
      SocketEntry **se = NULL;
      JLG(se, sd->sockets, fd);
      if (NULL != se && NULL != *se && caller == (*se)->pid) {
        if (0 > close(fd))
          return_socket_error(sd, fd, errno);
        else
          return_socket_closed_pid(sd, fd, caller);
        socket_entry_destroy(*se, sd);
        int rc = 0; /* don't care about the result of the judy delete */
        JLD(rc, sd->sockets, fd);
      } else {
        return_socket_bad_pid(sd, fd, caller); /* programmer messed up */
      }
      /* Only now release the emulator thread */
      set_null_and_signal((const void **const)fd_ptr, sd);
      break;
    }

  case SPB_ASYNC_ACCEPT:
    {
      const int **const fd_ptr = (const int **const)command.data;
      const int fd = **fd_ptr;
      /* release the emulator thread - we've copied out everything
         we need */
      set_null_and_signal((const void **const)fd_ptr, sd);
      SocketEntry **se = NULL;
      JLG(se, sd->sockets, fd);
      if (NULL != se && NULL != *se && LISTEN_SOCKET == (*se)->type) {
        Word_t index = -1;
        ErlDrvTermData **pid_ptr_found = NULL;
        /* find the last present index in the list of acceptors */
        JLL(pid_ptr_found, (*se)->socket.listen_socket.acceptors, index);
        if (NULL == pid_ptr_found)
          index = 0;
        else
          ++index;

        ErlDrvTermData *pid =
          (ErlDrvTermData *)driver_alloc(sizeof(ErlDrvTermData));
        if (NULL == pid)
          driver_failure(sd->port, -1);
        *pid = caller;  /* copy the calling pid into the memory just
                           allocated */

        ErlDrvTermData **pid_ptr = NULL;
        JLI(pid_ptr, (*se)->socket.listen_socket.acceptors, index);
        *pid_ptr = pid; /* make the array entry point at the memory
                           allocated */

        if (0 == index) /* if we're the first acceptor, enable the
                           watcher */
          ev_io_start(sd->epoller, (*se)->watcher);
        return_ok_fd_pid(sd, caller, fd);
      } else {
        return_socket_bad_pid(sd, fd, caller); /* programmer messed up */
      }
      break;
    }

  case SPB_ASYNC_RECV:
    {
      const SocketAction **const sa_ptr =
        (const SocketAction **const)command.data;
      SocketAction sa = **sa_ptr;
      /* release the emulator thread - we've copied out everything we
         need */
      set_null_and_signal((const void **const)sa_ptr, sd);
      SocketEntry **se = NULL;
      JLG(se, sd->sockets, sa.fd);
      if (NULL != se && NULL != *se && CONNECTED_SOCKET == (*se)->type &&
          caller == (*se)->pid) {
        int64_t old_quota = (*se)->socket.connected_socket.quota;
        (*se)->socket.connected_socket.quota = sa.value;
        if (0 == sa.value && 0 != old_quota)
          ev_io_stop(sd->epoller, (*se)->watcher);
        else if (0 != sa.value && 0 == old_quota)
          ev_io_start(sd->epoller, (*se)->watcher);
      } else {
        return_socket_bad_pid(sd, sa.fd, caller); /* programmer messed up */
      }
      break;
    }
  }
}


/********************************
 *  ev_loop thread entry point  *
 ********************************/

static void *spb_ev_start(void *arg) {
  SpbData *const sd = (SpbData*)arg;

  erl_drv_mutex_lock(sd->mutex);

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
  erl_drv_mutex_unlock(sd->mutex);

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
  sd->mutex = erl_drv_mutex_create("spb");
  if (NULL == sd->mutex)
    return ERL_DRV_ERROR_GENERAL;

  sd->sockets = (Pvoid_t)NULL;
  sd->cond = erl_drv_cond_create("spb");

  if (0 != erl_drv_thread_create("spb", &(sd->tid), &spb_ev_start, sd, NULL))
    return ERL_DRV_ERROR_GENERAL;

  await_epoller(sd);
  command_set_and_notify(SPB_ASYNC_START, NULL, sd);

  return (ErlDrvData)sd;
}

static void spb_stop(const ErlDrvData drv_data) {
  SpbData *const sd = (SpbData*)drv_data;

  command_set_and_notify(SPB_ASYNC_EXIT, NULL, sd);
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

  erl_drv_mutex_destroy(sd->mutex);
  erl_drv_cond_destroy(sd->cond);

  Word_t freed = 0;
  JLFA(freed, sd->sockets);

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
