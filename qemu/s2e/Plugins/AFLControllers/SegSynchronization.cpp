/*
 * SegSynchronization.cpp
 *
 *  Created on: 2016年5月3日
 *      Author: epeius
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "SegSynchronization.h"
extern int errno;

int SegSynchronization::initsem(key_t semkey)
{
    int status = 0, semid;
    if ((semid = semget(semkey, 1, SEMPERM | IPC_CREAT | IPC_EXCL)) == -1) {
        if (errno == EEXIST)               //EEXIST: already exists?
            semid = semget(semkey, 1, 0);
    } else {
        semun arg;
        arg.val = 1;
        status = semctl(semid, 0, SETVAL, arg);
    }
    if (semid == -1 || status == -1) {
        perror("initsem failed");
        return (-1);
    }
    /*all ok*/
    m_semid = semid;
    return (0);
}

int SegSynchronization::release(void)
{
    struct sembuf v_buf;

    v_buf.sem_num = 0;
    v_buf.sem_op = 1;    //add segmo +1
    v_buf.sem_flg = SEM_UNDO;

    int rc;
    while ((rc = semop(m_semid, &v_buf, 1)) == -1) {
        if (errno != EINTR) {
            perror("v(semid)failed");
            exit(1);
        }
    }
    return (0);
}

int SegSynchronization::acquire(void)
{
    struct sembuf p_buf;

    p_buf.sem_num = 0;
    p_buf.sem_op = -1;        //decrease 1
    p_buf.sem_flg = SEM_UNDO;

    int rc;
    while ((rc = semop(m_semid, &p_buf, 1)) == -1) {
        if (errno != EINTR) {
            perror("p(semid)failed");
            exit(1);
        }
    }
    return (0);
}
SegSynchronization::~SegSynchronization()
{
    if ((semctl(m_semid, 0, IPC_RMID)) < 0) {
        perror("semctl error");
        exit(-1);
    }
}
