#ifndef BLOM_H
#define BLOM_H


class Blom
{
public:
    Blom();
    void create_close_key(unsigned int *open_key,unsigned int *close_key);
    unsigned int create_session_key(unsigned int *open_key_p,unsigned int *close_key_y);
private:
    unsigned int p=4294967294;
    unsigned int matrix[8][8] {
        { 252, 238, 221, 17, 207, 110, 4,56},
        { 238, 193, 145, 2, 209, 33, 12,167},
        { 221, 145, 131, 85, 9, 241, 113,255},
        { 17, 2, 85, 44, 128, 72, 209, 31},
        { 207, 209, 9, 128, 68, 95, 239,2},
        { 110, 33, 241, 72, 95, 124, 88,229},
        { 4, 12, 113, 209, 239, 88, 71,178},
        { 56, 167, 255, 31, 2, 229, 178,5}
    };
};

#endif // BLOM_H
