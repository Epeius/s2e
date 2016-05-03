/*
 * SegSynchronization.h
 *
 *  Created on: 2016年5月3日
 *      Author: epeius
 */

#ifndef SEGSYNCHRONIZATION_H_
#define SEGSYNCHRONIZATION_H_

//synchronization
#define SEMPERM 0600

typedef union _semun
{
    int val;
    struct semid_ds *buf;
    ushort *array;
} semun;

class SegSynchronization
{
private:
    int m_semid;
public:
    SegSynchronization()
    {
        m_semid = 0;
    }
    ~SegSynchronization();
    int initsem(int); // argument is SMKEY
    int release(void);
    int acquire(void);
    int getSemId(void) const
    {
        return m_semid;
    }
};

#endif /* SEGSYNCHRONIZATION_H_ */
