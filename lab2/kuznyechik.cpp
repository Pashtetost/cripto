#include "kuznyechik.h"


//сложение двух двоичных векторов по модулю 2
void kuznyechik_X(uint8_t *first, uint8_t *second, uint8_t *result){
    for (int i = 0; i < BLOCK_SIZE; i++){
        result[i] = first[i] ^ second[i]; // побайтовый xor двух векторов
    }
}

//умножение над неприводимым полиномом x^8 + x^7 + x^6 + x + 1
uint8_t kuznyechik_GF_mul(uint8_t first, uint8_t second)
{
    uint8_t result = 0;
    while (second) { // пока второй множитель не обратится в ноль
        if (second & 1)
            result ^= first; // xor результата и первого множителя
        first = (first << 1) ^ (first & 0x80 ? 0xC3 : 0x00); // сдвигаем первый множитель на один бит влево и xor-им либо с C3 либо с 0
        second >>= 1; //второй множитель сдвигаем на один бит вправо
    }
    return result;
}

//R-преобразование
// реализуется с помощью линейного регистра сдвига с обратной связью (РСЛОС)
void kuznyechik_R(uint8_t* input)
{
    unsigned char l_vec[BLOCK_SIZE] = {// Вектор для РСЛОС (1, 148,...)
        0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
        0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
    };
    uint8_t buff;  // буфферный бит
    buff = input[15];	// так как l_vec[15] = 1

    for (int i = 14; i >= 0; i--) {
        input[i + 1] = input[i];// двигаем байты в сторону старшего разряда
        buff ^= kuznyechik_GF_mul(input[i], l_vec[i]); // а в буфферный элемент xor-им с результатотм умножения в поле Галуа байта входного вектора и байтом вектор констант
    }
    input[0] = buff; // последнему байту присваим значение из буффера
}

//L-преобразование
void kuznyechik_L(uint8_t* input)
{
    for (int i = 0 ; i < 16 ; i++) { // 16 раундов R преобразования
        kuznyechik_R(input);
    }
}

//S-преобразование
void kuznyechik_S(uint8_t *input){
    uint8_t Pi[] = {// S-блок определенный стандартом
        //  ?0/?8 ?1/?9 ?2/?a ?3/?b ?4/?c ?5/?d ?6/?e ?7/?f
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 	// 00..07
        0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 	// 08..0F
        0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 	// 10..17
        0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1, 	// 18..1F
        0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 	// 20..27
        0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F, 	// 28..2F
        0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 	// 30..37
        0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F, 	// 38..3F
        0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 	// 40..47
        0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC, 	// 48..4F
        0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 	// 50..57
        0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87, 	// 58..5F
        0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 	// 60..67
        0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1, 	// 68..6F
        0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 	// 70..77
        0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57, 	// 78..7F
        0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 	// 80..87
        0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03, 	// 88..8F
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 	// 90..97
        0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A, 	// 98..9F
        0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 	// A0..A7
        0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41, 	// A8..AF
        0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 	// B0..B7
        0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B, 	// B8..BF
        0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 	// C0..C7
        0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89, 	// C8..CF
        0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 	// D0..D7
        0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61, 	// D8..DF
        0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 	// E0..E7
        0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52, 	// E8..EF
        0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 	// F0..F7
        0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6, 	// F8..FF
    };
    for (int i = 0; i < BLOCK_SIZE; i++){
        input[i] = Pi[input[i]]; // выполнение перестановки элементов
    }
}

//Функция генерации раундовых ключей
round_keys kuznyechik_generate_keys(uint8_t* input_key)
{
    round_keys result;
    for(int i = 0 ; i < BLOCK_SIZE ; i++) // разбиваем ключ на два
    {
        result.keys[0].key[i] = input_key[i];
        result.keys[1].key[i] = input_key[i+BLOCK_SIZE];
    }
    one_key left = result.keys[1]; // состояние ливого блока
    one_key right = result.keys[0]; // состояние правого блока
    one_key buff; // промежуточный результат, хранит результаты:
    //xor-а правого блока с константым вектором Ci
    //затем результат S-преобразования
    //затем результат L-преобразования
    //и кончательно нужен для xor-а с левым блоком
    for(int k = 0 ; k < 4 ; k++) // 4 раза
    {
        for(int i = 0 ; i < 8 ; i++) // по 8 итераций стеи Фейстеля
        {
            one_key c; // вектор констант
            // задаем вектору с вид 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ??, где ?? номер итерации сети Фейстеля
            c.key[15] = 0x00; // последний элемент обнуляем
            for(int j = 0 ; j < k*8+i+1 ; j++){
                c.key[15]++; // инкрементируем необходимое количество раз, по номеру итерации сети фейстеля
            }
            for(int j = 0 ; j < BLOCK_SIZE-1 ; j++){
                if (j!=15){c.key[j] = 0x00;} // остальное заполняем нулями
            }
            kuznyechik_L(c.key); // выполняем L-преобразование для получения нужного вектора констант Ci
            kuznyechik_X(c.key, right.key, buff.key); // xor правого блока и вектора констант пишем в буффер
            kuznyechik_S(buff.key);// буффер прогоняем через S-преобразование
            kuznyechik_L(buff.key);// затем через L-преобразование
            kuznyechik_X(buff.key, left.key, buff.key);// xor-им буффер с левым блоком
            left = right; // меняем правый и левый блок метсами
            right = buff;
        }
        result.keys[k*2+2] = right; // после каждых 8 итераций сети Фейстеля левый и правый блок принимаем за раундовые ключи
        result.keys[k*2+3] = left;
    }
    return result;
}

//алгоритм шифрования
void kuznyechik_encrypt(uint8_t* input_key, uint8_t* plaintext, uint8_t* ciphertext){
    round_keys keys = kuznyechik_generate_keys(input_key); // генерируем раундовые ключи
    //если есть необходимость шифровать несколько блоков на одном и том же ключе, то можно сохранять сгенерированные ключи в память
    for(int i = 0 ; i < BLOCK_SIZE ; i++){ //открытый текст копируем
        ciphertext[i] = plaintext[i];
    }
    for(int i = 0 ; i < 9 ; i++){ // 9 полных раундов

        kuznyechik_X(ciphertext, keys.keys[i].key, ciphertext); // xor раундового ключа и блока текста
        kuznyechik_S(ciphertext); // S-преобразование
        kuznyechik_L(ciphertext); // L-преобразование
    }
    kuznyechik_X(ciphertext, keys.keys[9].key, ciphertext);// неполный раунд - xor с последним раундовым ключом
}

//Обратное R-преобразование
//Выполняется аналогично R-преобразованию
void kuznyechik_R_reverse(uint8_t* input)
{
    unsigned char l_vec[BLOCK_SIZE] = {
        0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
        0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
    };
    uint8_t buff;
    buff = input[0];

    for (int i = 0; i < 15; i++) { // но идем теперь от младшего к старшему
        input[i] = input[i + 1];
        buff ^= kuznyechik_GF_mul(input[i], l_vec[i]);
    }
    input[15] = buff;
}

//Обратное L-преобразование
void kuznyechik_L_reverse(uint8_t* input)
{
    for (int i = 0 ; i < 16 ; i++) {// 16 раундов обратного R-преобразование
        kuznyechik_R_reverse(input);
    }
}

// обратное S-преобразование
void kuznyechik_S_reverse(uint8_t *input){
    // выполняется анологисно S-преобразованию, но с другим S-блоком
    uint8_t reverse_Pi[] = {
        //  ?0/?8 ?1/?9 ?2/?a ?3/?b ?4/?c ?5/?d ?6/?e ?7/?f
        0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 	// 00..07
        0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91, 	// 08..0F
        0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 	// 10..17
        0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F, 	// 18..1F
        0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 	// 20..27
        0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7, 	// 28..2F
        0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 	// 30..37
        0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5, 	// 38..3F
        0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 	// 40..47
        0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F, 	// 48..4F
        0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 	// 50..57
        0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E, 	// 58..5F
        0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 	// 60..67
        0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B, 	// 68..6F
        0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 	// 70..77
        0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C, 	// 78..7F
        0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 	// 80..87
        0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36, 	// 88..8F
        0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 	// 90..97
        0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD, 	// 98..9F
        0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 	// A0..A7
        0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA, 	// A8..AF
        0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 	// B0..B7
        0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58, 	// B8..BF
        0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 	// C0..C7
        0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04, 	// C8..CF
        0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 	// D0..D7
        0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80, 	// D8..DF
        0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 	// E0..E7
        0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26, 	// E8..EF
        0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 	// F0..F7
        0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74	 	// F8..FF
    };
    for (int i = 0; i < BLOCK_SIZE; i++){
        input[i] = reverse_Pi[input[i]];
    }
}

//алгоритм дешифрования
//аналогичен алгоритму ширфрования
void kuznyechik_decrypt(uint8_t* input_key, uint8_t* ciphertext, uint8_t* plaintext){
    round_keys keys = kuznyechik_generate_keys(input_key);
    for(int i = 0 ; i < BLOCK_SIZE ; i++){
        plaintext[i] = ciphertext[i];
    }
    for(int i = 9 ; i > 0 ; i--){ // но раундовые ключи подаются в обратном порядке

        kuznyechik_X(plaintext, keys.keys[i].key, plaintext);
        kuznyechik_L_reverse(plaintext); // и сначала выполняется обратное L-преобразование
        kuznyechik_S_reverse(plaintext); // а затем обратное S-преобразование
    }
    kuznyechik_X(plaintext, keys.keys[0].key, plaintext);// неполный раунд
}