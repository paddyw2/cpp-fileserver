#include "server.h"

int main(int argc, char * argv[])
{
    server fileserver(argc, argv);
    fileserver.start_server();
    return 0;
}
