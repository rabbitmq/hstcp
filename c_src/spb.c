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
#define SOCKET_ERROR_SPEC_LEN  13
#define OK_FD_SPEC_LEN         12

#define LISTEN_SOCKET 1
#define CONNECTED_SOCKET 2

struct queueCell {
  uint8_t cmd;
  const void *data;
  struct queueCell *next;
};
typedef struct queueCell QueueCell;

typedef struct {
  ErlDrvPort     port;               /* driver port                                    */
  ErlDrvTermData pid;                /* driver pid                                     */
  ErlDrvTermData *no_such_command_atom_spec;
  ErlDrvTermData *ok_atom_spec;
  ErlDrvTermData *reader_error_spec; /* terms for errors from reader                   */
  ErlDrvTermData *socket_error_spec; /* terms for errors from socket                   */
  ErlDrvTermData *ok_fd_spec;        /* terms for ok results including a fd            */
  struct ev_loop *epoller;           /* our ev loop                                    */
  ErlDrvTid      tid;                /* the thread running our ev loop                 */
  ev_async       *async_watcher;     /* the async watcher used to talk to our thread   */
  ErlDrvMutex    *mutex;             /* mutex to safely enqueue commands to our thread */
  QueueCell      *cmd_q_head;        /* the head of that command queue                 */
  QueueCell      *cmd_q_tail;        /* the tail of that command queue                 */
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
  ErlDrvTermData pid;
} ConnectedSocket;

typedef union {
  ListenSocket listen_socket;
  ConnectedSocket connected_socket;
} Socket;

typedef struct {
  uint8_t type;
  int fd;
  ev_io *watcher;
  Socket socket;
} SocketEntry;

typedef struct {
  int fd;
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


/*****************************
 *  Command Queue Functions  *
 *****************************/

void enqueue_cmd_and_notify(uint8_t cmd, const void *const *const data, SpbData *const sd) {
  QueueCell *const cell = (QueueCell*)driver_alloc(sizeof(QueueCell));
  if (NULL == cell)
    driver_failure(sd->port, -1);

  cell->cmd = cmd;
  cell->data = data;
  cell->next = NULL;

  erl_drv_mutex_lock(sd->mutex);

  if (NULL != sd->cmd_q_tail)
    sd->cmd_q_tail->next = cell;

  sd->cmd_q_tail = cell;

  if (NULL == sd->cmd_q_head)
    sd->cmd_q_head = cell;

  erl_drv_mutex_unlock(sd->mutex);
  ev_async_send(sd->epoller, sd->async_watcher);
}

uint8_t dequeue_cmd(const void **const data, SpbData *const sd) {
  uint8_t result = SPB_ASYNC_UNDEFINED;

  erl_drv_mutex_lock(sd->mutex);
  QueueCell *const cell = sd->cmd_q_head;
  if (NULL != cell) {
    result = cell->cmd;
    *data = cell->data;
    sd->cmd_q_head = cell->next;

    if (cell == sd->cmd_q_tail)
      sd->cmd_q_tail = cell->next;

    driver_free(cell);
  }
  erl_drv_mutex_unlock(sd->mutex);

  return result;
}


/**********************
 *  Socket Functions  *
 **********************/

void return_socket_error(SpbData *const sd, const int error) {
  const char* error_str = strerror(error);
  sd->socket_error_spec[7] = (ErlDrvTermData)error_str;
  sd->socket_error_spec[8] = (ErlDrvUInt)strlen(error_str);
  driver_send_term(sd->port, sd->pid, sd->socket_error_spec, SOCKET_ERROR_SPEC_LEN);
  sd->socket_error_spec[7] = (ErlDrvTermData)NULL;
  sd->socket_error_spec[8] = 0;
}

void return_ok_fd(SpbData *const sd, const int fd) {
  sd->ok_fd_spec[7] = fd;
  driver_send_term(sd->port, sd->pid, sd->ok_fd_spec, OK_FD_SPEC_LEN);
  sd->ok_fd_spec[7] = 0;
}

int setnonblock(const int fd) { /* and turn off nagle */
  int flags = fcntl(fd, F_GETFL);
  flags |= O_NONBLOCK;
  flags |= O_NDELAY;
  return fcntl(fd, F_SETFL, flags);
}

void socket_listen(SpbData *const sd, Reader *const reader) {
  const int reuse = 1;
  const char *address = NULL;
  const uint64_t *address_len = NULL;
  const uint16_t *port;

  if (! read_binary(reader, &address, &address_len)) {
    return_reader_error(sd, reader);
    return;
  }
  if (! read_uint16(reader, &port)) {
    return_reader_error(sd, reader);
    return;
  }

  struct sockaddr_in addresslisten;
  const int socketlisten = socket(AF_INET, SOCK_STREAM, 0);

  if (socketlisten < 0) {
    return_socket_error(sd, errno);
    return;
  }

  /* strings coming from Erlang are not zero terminated, and the
     length won't include the 0 stop byte, so copy into a new array,
     ensuring we have a stop byte at the end. */
  char *const address2 = (char*) driver_alloc((*address_len)+1);
  if (NULL == address2) {
    return_reader_error(sd, reader);
    return;
  }

  address2[(*address_len)] = '\0';
  strncpy(address2, address, *address_len);

  memset(&addresslisten, 0, sizeof(addresslisten));

  addresslisten.sin_family = AF_INET;
  addresslisten.sin_port = htons(*port);
  const int inet_aton_res = inet_aton(address2, &(addresslisten.sin_addr));
  driver_free(address2);

  if (0 == inet_aton_res) { /* why does inet_aton return 0 on FAILURE?! */
    return_socket_error(sd, errno);
    return;
  }

  if (0 > bind(socketlisten,
               (struct sockaddr *)&addresslisten,
               sizeof(addresslisten))) {
    return_socket_error(sd, errno);
    return;
  }

  /* listen for incoming connections. set backlog to 128 */
  if (0 > listen(socketlisten, 128)) {
    return_socket_error(sd, errno);
    return;
  }

  /* turn on reuseaddr */
  if (0 > setsockopt(socketlisten,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &reuse,
                     sizeof(reuse))) {
    return_socket_error(sd, errno);
    return;
  }

  /* put socket into nonblocking mode - needed for libev */
  if (0 > setnonblock(socketlisten)) {
    return_socket_error(sd, errno);
    return;
  }

  const int *socketlisten_ptr = &socketlisten;
  const void **const socketlisten_ptr_ptr = (const void **const)&socketlisten_ptr;
  enqueue_cmd_and_notify(SPB_ASYNC_LISTEN, socketlisten_ptr_ptr, sd);
  await_null(socketlisten_ptr_ptr, sd);

  return_ok_fd(sd, socketlisten);
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
  enqueue_cmd_and_notify(SPB_ASYNC_CLOSE, fd_ptr_ptr, sd);
  await_null(fd_ptr_ptr, sd);
}

void socket_accept(SpbData *const sd, Reader *const reader) {
  const int64_t *fd64_ptr = NULL;
  if (! read_int64(reader, &fd64_ptr)) {
    return_reader_error(sd, reader);
    return;
  }
  ErlDrvTermData caller = sd->pid;
  SocketAction sa;
  sa.fd = (int)*fd64_ptr;
  sa.pid = caller;
  const SocketAction *sa_ptr = &sa;
  const void **sa_ptr_ptr = (const void **)&sa_ptr;
  enqueue_cmd_and_notify(SPB_ASYNC_ACCEPT, sa_ptr_ptr, sd);
  await_null(sa_ptr_ptr, sd);

}

/***********************
 *  ev_loop callbacks  *
 ***********************/

static void spb_ev_socket_read_cb(EV_P_ ev_io *, int);
static void spb_ev_listen_cb(EV_P_ ev_io *, int);

SocketEntry *listen_socket_create(const int fd, SpbData *const sd) {
  SocketEntry *const se = (SocketEntry*)driver_alloc(sizeof(SocketEntry));
  if (NULL == se)
    driver_failure(sd->port, -1);

  se->type = LISTEN_SOCKET;
  se->fd = fd;
  se->socket.listen_socket.acceptors = (Pvoid_t)NULL;

  se->watcher = (ev_io*)driver_alloc(sizeof(ev_io));
  if (NULL == se->watcher)
    driver_failure(sd->port, -1);

  ev_io_init(se->watcher, spb_ev_listen_cb, fd, EV_READ);
  se->watcher->data = sd;

  return se;
}

SocketEntry *connected_socket_create(const int fd, ErlDrvTermData pid, SpbData *const sd) {
  SocketEntry *const se = (SocketEntry*)driver_alloc(sizeof(SocketEntry));
  if (NULL == se)
    driver_failure(sd->port, -1);

  se->type = CONNECTED_SOCKET;
  se->fd = fd;
  se->socket.connected_socket.pid = pid;

  se->watcher = (ev_io*)driver_alloc(sizeof(ev_io));
  if (NULL == se->watcher)
    driver_failure(sd->port, -1);

  ev_io_init(se->watcher, spb_ev_socket_read_cb, fd, EV_READ);
  se->watcher->data = sd;

  return se;
}

void socket_entry_destroy(SocketEntry *se, SpbData *const sd) {
  Word_t freed = 0;
  switch (se->type) {

  case LISTEN_SOCKET:
    ev_io_stop(sd->epoller, se->watcher);
    driver_free(se->watcher);
    JLFA(freed, se->socket.listen_socket.acceptors);
    break;

  case CONNECTED_SOCKET:
    ev_io_stop(sd->epoller, se->watcher);
    driver_free(se->watcher);
    break;

  }
  driver_free(se);
}

static void spb_ev_socket_read_cb(EV_P_ ev_io *w, int revents) {
}

static void spb_ev_listen_cb(EV_P_ ev_io *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  struct sockaddr_in client_addr;
  socklen_t client_len;
  int client_sd;

  int rc = 0;
  Word_t index = 0;
  ErlDrvTermData *const *pid = NULL;
  SocketEntry **se = NULL;

  JLG(se, sd->sockets, w->fd); /* find the SocketEntry for w->fd */
  if (NULL != se && LISTEN_SOCKET == (*se)->type) {
    /* find first entry in acceptors */
    JLBC(pid, (*se)->socket.listen_socket.acceptors, 1, index);

    if (NULL != pid) {
      /* delete that entry from acceptors */
      JLD(rc, (*se)->socket.listen_socket.acceptors, index);

      client_len = sizeof(client_addr);
      memset(&client_addr, 0, client_len);
      client_sd = accept(w->fd, (struct sockaddr *)&client_addr, &client_len);

      if (0 > setnonblock(client_sd))
        driver_failure(sd->port, -1);

      sd->ok_fd_spec[7] = client_sd;
      driver_send_term(sd->port, **pid, sd->ok_fd_spec, OK_FD_SPEC_LEN);
      sd->ok_fd_spec[7] = 0;

      driver_free(*pid);

      /* figure out if there are more pending acceptors */
      JLC(index, (*se)->socket.listen_socket.acceptors, 0, -1);
      if (0 == index)
        ev_io_stop(EV_A_ w);

      JLI(se, sd->sockets, client_sd);
      *se = connected_socket_create(client_sd, **pid, sd);
    } else {
      driver_failure(sd->port, -1);
    }
  } else {
    driver_failure(sd->port, -1);
  }
}

static void spb_ev_async_cb(EV_P_ ev_async *w, int revents) {
  SpbData *const sd = (SpbData *const)(w->data);
  const void *data = NULL;

  switch (dequeue_cmd(&data, sd)) {

  case SPB_ASYNC_START:
    driver_send_term(sd->port, sd->pid, sd->ok_atom_spec, ATOM_SPEC_LEN);
    break;

  case SPB_ASYNC_EXIT:
    ev_async_stop(EV_A_ w);
    ev_unloop(EV_A_ EVUNLOOP_ALL);
    ev_loop_destroy(EV_A);
    break;

  case SPB_ASYNC_LISTEN:
    {
      SocketEntry **se = NULL;
      const int **const fd_ptr = (const int **const)data;
      const int fd = **fd_ptr;
      *fd_ptr = NULL;
      erl_drv_cond_signal(sd->cond);
      JLI(se, sd->sockets, fd);
      *se = listen_socket_create(fd, sd);
      break;
    }

  case SPB_ASYNC_CLOSE:
    {
      SocketEntry **se = NULL;
      const int **const fd_ptr = (const int **const)data;
      const int fd = **fd_ptr;
      JLG(se, sd->sockets, fd);
      if (NULL != se) {
        int rc = 0;
        if (0 > close(fd))
          return_socket_error(sd, errno);
        else
          driver_send_term(sd->port, sd->pid, sd->ok_atom_spec, ATOM_SPEC_LEN);
        socket_entry_destroy(*se, sd);
        JLD(rc, sd->sockets, fd);
      }
      *fd_ptr = NULL;
      erl_drv_cond_signal(sd->cond);
      break;
    }

  case SPB_ASYNC_ACCEPT:
    {
      SocketEntry **se = NULL;
      const SocketAction **const sa_ptr = (const SocketAction **const)data;
      SocketAction sa = **sa_ptr;
      *sa_ptr = NULL;
      erl_drv_cond_signal(sd->cond);
      JLG(se, sd->sockets, sa.fd);
      if (NULL != se && LISTEN_SOCKET == (*se)->type) {
        Word_t index = -1;
        ErlDrvTermData **pid_ptr_found = NULL;
        ErlDrvTermData **pid_ptr = NULL;
        /* find the last present index */
        JLL(pid_ptr_found, (*se)->socket.listen_socket.acceptors, index);
        if (NULL == pid_ptr_found)
          index = 0;
        else
          index++;
        JLI(pid_ptr, (*se)->socket.listen_socket.acceptors, index);
        ErlDrvTermData *pid = (ErlDrvTermData *)driver_alloc(sizeof(ErlDrvTermData));
        if (NULL == pid)
          driver_failure(sd->port, -1);
        *pid = sa.pid;  /* copy the calling pid into the memory just allocated */
        *pid_ptr = pid; /* make the array entry point at the memory allocated */
        if (0 == index) /* if we're the first acceptor, enable the watcher */
          ev_io_start(sd->epoller, (*se)->watcher);
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

  erl_drv_mutex_unlock(sd->mutex);
  erl_drv_cond_signal(sd->cond);

  printf("poller started\r\n");
  ev_loop(sd->epoller, 0);
  printf("poller stopping\r\n");
  return NULL;
}


/*****************************
 *  Erlang Driver Callbacks  *
 *****************************/

static int spb_init() {
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
  sd->no_such_command_atom_spec[1] = driver_mk_atom("spb_reply");
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
  sd->ok_atom_spec[1] = driver_mk_atom("spb_reply");
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
  sd->reader_error_spec[1] = driver_mk_atom("spb_reply");
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
  sd->socket_error_spec[1] = driver_mk_atom("spb_reply");
  sd->socket_error_spec[2] = ERL_DRV_PORT;
  sd->socket_error_spec[3] = driver_mk_port(port);
  sd->socket_error_spec[4] = ERL_DRV_ATOM;
  sd->socket_error_spec[5] = driver_mk_atom("socket_error");
  sd->socket_error_spec[6] = ERL_DRV_STRING;
  sd->socket_error_spec[7] = (ErlDrvTermData)NULL;
  sd->socket_error_spec[8] = 0;
  sd->socket_error_spec[9] = ERL_DRV_TUPLE;
  sd->socket_error_spec[10] = 2;
  sd->socket_error_spec[11] = ERL_DRV_TUPLE;
  sd->socket_error_spec[12] = 3;

  sd->ok_fd_spec = (ErlDrvTermData*)
    driver_alloc(OK_FD_SPEC_LEN * sizeof(ErlDrvTermData));

  if (NULL == sd->ok_fd_spec)
    return ERL_DRV_ERROR_GENERAL;

  sd->ok_fd_spec[0] = ERL_DRV_ATOM;
  sd->ok_fd_spec[1] = driver_mk_atom("spb_reply");
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

  sd->cmd_q_head = NULL;
  sd->cmd_q_tail = NULL;
  sd->sockets = (Pvoid_t)NULL;
  sd->cond = erl_drv_cond_create("spb");

  if (0 != erl_drv_thread_create("spb", &(sd->tid), &spb_ev_start, sd, NULL))
    return ERL_DRV_ERROR_GENERAL;

  await_epoller(sd);
  enqueue_cmd_and_notify(SPB_ASYNC_START, NULL, sd);

  return (ErlDrvData)sd;
}

static void spb_stop(const ErlDrvData drv_data) {
  Word_t freed = 0;
  SpbData *const sd = (SpbData*)drv_data;

  enqueue_cmd_and_notify(SPB_ASYNC_EXIT, NULL, sd);
  erl_drv_thread_join(sd->tid, NULL);

  driver_free((char*)sd->no_such_command_atom_spec);
  driver_free((char*)sd->ok_atom_spec);
  driver_free((char*)sd->reader_error_spec);
  driver_free((char*)sd->socket_error_spec);
  driver_free((char*)sd->ok_fd_spec);
  driver_free((char*)sd->async_watcher);
  erl_drv_mutex_destroy(sd->mutex);
  JLFA(freed, sd->sockets);
  erl_drv_cond_destroy(sd->cond);
  driver_free((char*)drv_data);
}

static void spb_outputv(ErlDrvData drv_data, ErlIOVec *const ev) {
  Reader reader;
  ErlDrvTermData* spec = NULL;
  const uint8_t* command = &spb_invalid_command;
  SpbData *const sd = (SpbData*)drv_data;
  sd->pid = driver_caller(sd->port);
  /* dump_ev(ev); */
  make_reader(ev, &reader);
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
