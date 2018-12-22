#include "blom.h"

Blom::Blom()
{

}

void Blom::create_close_key(unsigned int *open_key, unsigned int *close_key)
{
    for (int ix = 0; ix < 8; ix++)
     {
         close_key[ix] = 0;
         for (int jx = 0; jx < 8; jx++)
         {
             close_key[ix] += matrix[ix][jx] * open_key[jx];
         }
        close_key[ix]=close_key[ix]%p;
     }

}

unsigned int Blom::create_session_key(unsigned int *open_key_p, unsigned int *close_key_y)
{
    unsigned int session_key=0;
    for (int i = 0; i < 8; i++)
     {
         session_key+=close_key_y[i]*open_key_p[i];
     }
    session_key=session_key%p;
    return session_key;
}


