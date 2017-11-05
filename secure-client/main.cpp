#include "client.h"

int main(int argc, char * argv[])
{
    client fileclient(argc, argv);
    fileclient.send_cipher_nonce();
    fileclient.receive_challenge();
    fileclient.make_request();
    fileclient.close_socket();
    cout << "Finishing..." << endl;
    return 0;
}
