#include <cassert>
#include <pthread.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include "TCPTrack.h"
#include "AppError.h"
#include "PcapError.h"
#include "GenericError.h"
#include "defs.h"

TCPTrack *app=NULL;

pthread_cond_t quitflag=PTHREAD_COND_INITIALIZER;
pthread_mutex_t quitflag_mutex=PTHREAD_MUTEX_INITIALIZER;


TCPTrack::TCPTrack()
{
	ferr="";
	remto=2;
	fastmode=false;
	pthread_mutex_init( &ferr_lock, NULL );
}

void TCPTrack::run( int argc, char **argv )
{
	struct config cf = parseopts(argc,argv);

	remto=cf.remto;
	fastmode=cf.fastmode;
	detect=cf.detect;
	promisc=cf.promisc;

	c = new TCContainer();
	pb = new PacketBuffer();
	s = new Sniffer();
	//ui = new TextUI(c);

	try
	{
		s->dest(pb); // sniffer, send your packets to PacketBuffer
		pb->dest(c); // PacketBuffer, send your packets to the TCContainer

		// init() on these objects performs constructor-like actions,
		// only they may throw exceptions. Constructors don't.
		//ui->init();
		s->init(cf.iface,cf.fexp,cf.test_file);
		pb->init();

		// now let these objects run the application.
		// just sit here until someone calls shutdown(),
		// which sets the quitflag condition variable.
		pthread_mutex_lock(&quitflag_mutex);
		pthread_cond_wait(&quitflag,&quitflag_mutex);
		pthread_mutex_unlock(&quitflag_mutex);

		/* Print the tcp_sessions */
		std::cout<<"reached end"<<endl;
		SortedIterator *i = c->getSortedIteratorPtr();
		/* TODO: move this to a new function */
		while( TCPConnection *ic=i->getNext() )
		{
			string tcp_state;
			if ((ic->getState() == TCP_STATE_CLOSED || ic->getState() == TCP_STATE_RESET)
					&& (time(NULL) - ic->getLastPktTimestamp() > app->remto ))
			{
				continue;
			}
			if( ic->getState() == TCP_STATE_SYN_SYNACK )
				tcp_state = "SYN_SENT";
			else if( ic->getState() == TCP_STATE_SYNACK_ACK )
				tcp_state = "SYN|ACK-ACK";
			else if( ic->getState() == TCP_STATE_UP )
				tcp_state = "ESTABLISHED";
			else if( ic->getState() == TCP_STATE_FIN_FINACK )
				tcp_state = "CLOSING";
			else if( ic->getState() == TCP_STATE_CLOSED )
				tcp_state = "CLOSED";
			else if( ic->getState() == TCP_STATE_RESET )
				tcp_state = "RESET";

			std::cout<<std::setw(15)<<ic->srcAddr().ptr()<<":"<<std::setw(5)<<std::left<<ic->srcPort()<<"<->"<<std::setw(15)<<std::right<<ic->dstAddr().ptr()<<":"<<std::setw(5)<<std::left<<ic->dstPort()<<":"<<tcp_state<<endl;
			//printw("%s:%d", ic->srcAddr().ptr(), ic->srcPort() );

			//printw("%s:%d", ic->dstAddr().ptr(), ic->dstPort());
			#if 0
			if( ic->getState() == TCP_STATE_SYN_SYNACK )
				printw("SYN_SENT");
			else if( ic->getState() == TCP_STATE_SYNACK_ACK )
				printw("SYN|ACK-ACK");
			else if( ic->getState() == TCP_STATE_UP )
				printw("ESTABLISHED");
			else if( ic->getState() == TCP_STATE_FIN_FINACK )
				printw("CLOSING");
			else if( ic->getState() == TCP_STATE_CLOSED )
				printw("CLOSED");
			else if( ic->getState() == TCP_STATE_RESET )
				printw("RESET");
			#endif

		}


		// if an exception happened in another thread, it will be passed
		// to us via the fatal() method, which puts the error in string
		// form in this ferr variable.
		// TODO: This ferr thing is sloppy. should pass an actual
		// exception object.
		if( ferr != "" )
			throw GenericError(ferr);

		// shut everything down cleanly.
		//ui->stop();
		s->dest();
		pb->dest();
		c->stop();

		delete s;
	}
	catch( const AppError &e )
	{
		// detach the objects from each other.
		// other threads may be running after a delete and may follow a
		// bad pointer to a just deleted object otherwise.
		s->dest();
		pb->dest();

		//delete ui;
		delete s;
		delete pb;
		delete c;

		// This tries to reset the terminal to a sane mode, in case
		// TextUI couldn't do it cleanly.
		//TextUI::reset();

		cout << e.msg() <<endl;
	}
}

// quit tcptrack
void TCPTrack::shutdown()
{
	pthread_mutex_lock(&quitflag_mutex);
	pthread_cond_signal(&quitflag);
	pthread_mutex_unlock(&quitflag_mutex);
}

// TODO: This ferr thing is sloppy. should pass an actual
// exception object.
void TCPTrack::fatal( string msg )
{
	assert( pthread_mutex_lock(&ferr_lock) == 0 );

	if( ferr != "" )
	{
		// there can be only one fatal error at once
		assert( pthread_mutex_unlock(&ferr_lock) );
		return;
	}

	ferr = msg;
	shutdown();
	assert( pthread_mutex_unlock(&ferr_lock) == 0 );
}

void printusage(int argc,char **argv)
{
	printf("Usage: %s [-fhv] [-r <seconds>] [<filter expression>] [-T <pcap file]\n",argv[0]);
}

struct config parseopts(int argc, char **argv)
{
	int o;
	struct config cf;
	cf.remto=CLOSED_PURGE;
	cf.fastmode=false;
	cf.promisc=false;
	cf.detect=true;
	cf.test_file=NULL;
	cf.iface = NULL;
	bool got_iface=false;

	while( (o=getopt(argc,argv,"hvfr:T:")) > 0 )
	{
		if( o=='h' )
		{
			printusage(argc,argv);
			exit(0);
		}
		if( o=='v' )
		{
			printf("%s v%s\n",PACKAGE,VERSION);
			exit(0);
		}
		if( o=='r' )
			cf.remto = atoi(optarg);
		if( o=='f' )
			cf.fastmode=true;
		if( o=='T' )
		{
			cf.test_file=optarg;
			got_iface=true; // Don't complain if we don't get an interface. A test file is OK too.
		}
	}

	if( ! got_iface ) {
		printusage(argc,argv);
		exit(1);
	}

	std::string fexp;
	cf.fexp = strdup(fexp.c_str());
	return cf;
}
