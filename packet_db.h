#ifndef PACKET_DB_H
#define PACKET_DB_H

#define MAX_PEOPLE 10
#define MAX_NAME_LEN 32
#define MAX_INTEREST_LEN 32

typedef struct {
    char name[MAX_NAME_LEN];
    char interest[MAX_INTEREST_LEN];
} Person;

extern Person database[MAX_PEOPLE];

#endif
