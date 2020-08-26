#ifndef  _MAIN_H_
#define  _MAIN_H_

#include <sys/types.h>
#include <time.h>

#include <string>
#include <list>
#include <mutex>

using namespace std;

/*
 * Thread must sleep after started up, till it got its
 * running-token.
 */
enum ThreadToken {
	TKN_NONE,
	TKN_RECVER,
	TKN_SENDER,
	TKN_ALL,
};
extern int g_Token;
static inline void threadGetToken(ThreadToken token) {
	while(g_Token < token)
		usleep(100000);
}
static inline void threadPutToken() {
	g_Token++;
}


#endif /* _MAIN_H_ */
