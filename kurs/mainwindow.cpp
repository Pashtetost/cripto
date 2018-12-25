#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

}

MainWindow::~MainWindow()
{
    delete ui;
}



void MainWindow::on_pbCon_clicked()
{

    //получение дескриптора
    if(CryptAcquireContext(
        &hProvCrypt,               // Дескриптор CSP
        (const wchar_t*) ui->leCon->text().utf16(),                  // Имя контейнера
        NULL,                      // Использование провайдера по умолчанию
        PROV_GOST_2012_256,         // Тип провайдера
        0))                        // Значения флагов
    {
        // Получение ключевой пары
        if(CryptGetUserKey(
                    hProvCrypt,   // Дескриптор CSP
                    AT_KEYEXCHANGE,   // Спецификация ключа
                    &hKeyCrypt))         // Дескриптор ключа
        {
            ui->lCon->setText(ui->leCon->text());
        }
        else
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Дискриптор на ключевую пару не получен.");
        }

    } else
    {
        // Создание нового контейнера.
                if(!CryptAcquireContext(
                    &hProvCrypt,
                    (const wchar_t*) ui->leCon->text().utf16(),
                    NULL,
                    PROV_GOST_2012_256,
                    CRYPT_NEWKEYSET))
                {
                     QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Контейнер не создан.");
                }
            // Криптографический контекст с ключевым контейнером доступен. Получение
            // имени ключевого контейнера.
                // Генерация ключевой пары
                if(!CryptGenKey(
                            hProvCrypt,
                            AT_KEYEXCHANGE,
                            CRYPT_EXPORTABLE,
                            &hKeyCrypt))
            {
                // Ошибка получении имени ключевого контейнера
                QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Дискриптор на ключевую пару не получен.");
            } else
            {
                ui->lCon->setText(ui->leCon->text());
            }
    }
    if(!CryptGenKey(
            hProvCrypt,
            CALG_G28147,
            0,
            &hSessionKey))
        {
             QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка генерации сессионного ключа.");
        }
}

void MainWindow::on_pbCon_2_clicked()
{

    //получение дескриптора
    if(CryptAcquireContext(
        &hProvSign,               // Дескриптор CSP
        (const wchar_t*) ui->leCon_2->text().utf16(),                  // Имя контейнера
        NULL,                      // Использование провайдера по умолчанию
        PROV_GOST_2012_256,         // Тип провайдера
        0))                        // Значения флагов
    {
        // Получение ключевой пары
        if(CryptGetUserKey(
                    hProvSign,   // Дескриптор CSP
                    AT_SIGNATURE,   // Спецификация ключа
                    &hKeySign))         // Дескриптор ключа
        {
            ui->lCon_2->setText(ui->leCon_2->text());
        }
        else
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Дискриптор на ключевую пару не получен.");
        }

    } else
    {
        // Создание нового контейнера.
                if(!CryptAcquireContext(
                    &hProvCrypt,
                    (const wchar_t*) ui->leCon_2->text().utf16(),
                    NULL,
                    PROV_GOST_2012_256,
                    CRYPT_NEWKEYSET))
                {
                     QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Контейнер не создан.");
                }
            // Криптографический контекст с ключевым контейнером доступен. Получение
            // имени ключевого контейнера.
                // Генерация ключевой пары
                if(!CryptGenKey(
                            hProvCrypt,
                            AT_SIGNATURE,
                            CRYPT_EXPORTABLE,
                            &hKeySign))
            {
                // Ошибка получении имени ключевого контейнера
                QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Дискриптор на ключевую пару не получен.");
            } else
            {
                ui->lCon_2->setText(ui->leCon_2->text());
            }
    }
}

void MainWindow::on_pbFile_clicked()
{
     Filename=QFileDialog::getOpenFileName(0, "Выбор файла", "C:/Users/pasht/Desktop", 0);
     ui->lFile->setText(Filename);
}

void MainWindow::on_pbEncrypt_clicked()
{
    if(!crypt(1))
    {
        QMessageBox::information(NULL,QObject::tr("Шифрование успешено"), "Шифрование файла прошло успешно.");
    }
}

void MainWindow::on_pbDecrypt_clicked()
{
    if(!crypt(0))
    {
        QMessageBox::information(NULL,QObject::tr("Дешифрование успешено"), "Дешифрование файла прошло успешно.");
    }
}

void MainWindow::on_pbSign_clicked()
{
        DWORD dwSigLen;
        DWORD dwBlobLen;
        DWORD cbHash;
        BYTE *pbSignature = NULL;
        FILE *signature;

        //Открываем файл
        std::ifstream file(Filename.toLocal8Bit().data());
        //Получаем длинну файла
        file.seekg( 0, std::ios::end );
        size_t length = file.tellg();
        BYTE *pbBuffer= new BYTE[length];
        file.seekg(0, std::ios::beg);
        file.read((char *)pbBuffer, length);
        file.close();

        DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer)+1);

    if(!CryptExportKey(
            hKeySign,
            0,
            PUBLICKEYBLOB,
            0,
            NULL,
            &dwBlobLen))
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении длинны открытого ключа произошла ошибка.");
        }
        //--------------------------------------------------------------------
        // Распределение памяти под pbKeyBlob.

        pbKeyBlob = (BYTE*)malloc(dwBlobLen);
        if(!pbKeyBlob)
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти под открытый ключ произошла ошибка.");

        // Сам экспорт в ключевой BLOB.
        if(!CryptExportKey(
            hKeySign,
            0,
            PUBLICKEYBLOB,
            0,
            pbKeyBlob,
            &dwBlobLen))
        {
             QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При экспортировании открытого ключа произошла ошибка.");
        }

        FILE * publickey;
        if(!(publickey = fopen((Filename + ".sign.publickey").toLocal8Bit().data(), "w+b")))
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При записи открытого ключа в файл произошла ошибка.");
        fwrite(pbKeyBlob, 1, dwBlobLen, publickey);
        fclose(publickey);

        //--------------------------------------------------------------------
        // Создание объекта функции хеширования.

        if(!CryptCreateHash(
            hProvSign,
            CALG_GR3411_2012_256,
            0,
            0,
            &hHash))
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При создании объекта хеш функции возникла ошибка.");
        }
        // Вычисление криптографического хеша буфера.

          if(!CryptHashData(
              hHash,
              pbBuffer,
              dwBufferLen,
              0))
          {
               QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении хэша содержимого файла произошла ошибка.");
          }

          // Определение размера подписи и распределение памяти.
          dwSigLen = 0;
          if(!CryptSignHash(
              hHash,
              AT_SIGNATURE,
              NULL,
              0,
              NULL,
              &dwSigLen))
          {
              QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении размера буфера для подписи произошла ошибка.");
          }
          //--------------------------------------------------------------------
              // Распределение памяти под буфер подписи.

              pbSignature = (BYTE *)malloc(dwSigLen);
              if(!pbSignature)
                  QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти для подписи ошибка.");

              // Подпись объекта функции хеширования.
              if(!CryptSignHash(
                  hHash,
                  AT_SIGNATURE,
                  NULL,
                  0,
                  pbSignature,
                  &dwSigLen))
              {
                  QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При подписании хэша файла произошла ошибка.");
              }


              if(!(signature = fopen((Filename+".sign").toLocal8Bit().data(), "w+b")))
                  QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При записи подписи в файл произошла ошибка.");

              fwrite(pbSignature, 1, dwSigLen, signature);
              QMessageBox::information(NULL,QObject::tr("Подпись"), "Файл успешно подписан.");
              // Уничтожение объекта функции хеширования.
              if(hHash)
                  CryptDestroyHash(hHash);

}

void MainWindow::on_pbCheck_clicked()
{
    DWORD dwSigLen;
    DWORD dwBlobLen;
    BYTE *pbSignature = NULL;

    //Открываем файл
    std::ifstream file(Filename.toLocal8Bit().data());
    //Получаем длинну файла
    file.seekg( 0, std::ios::end );
    size_t length = file.tellg();
    BYTE *pbBuffer= new BYTE[length];
    file.seekg(0, std::ios::beg);
    file.read((char *)pbBuffer, length);
    file.close();

    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer)+1);

    //Открываем файл подписи
    std::ifstream signfile((Filename + ".sign").toLocal8Bit().data());
    dwSigLen = 64;
    pbSignature = (BYTE *)malloc(dwSigLen);
    if(!pbSignature)
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти для подписи ошибка.");
    signfile.read((char*)pbSignature,(size_t)dwSigLen);
    signfile.close();

    //Открываем файл открытого ключа
    std::ifstream publickey_file((Filename + ".sign.publickey").toLocal8Bit().data());
    dwBlobLen = 101;
    BYTE * pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    if(!pbKeyBlob)
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти для открытого ключа произошла ошибка.");
    publickey_file.read((char*)pbKeyBlob,(size_t)dwBlobLen);

    publickey_file.close();

    //--------------------------------------------------------------------
    // Создание объекта функции хеширования.

    if(!CryptCreateHash(
        hProvSign,
        CALG_GR3411_2012_256,
        0,
        0,
        &hHash))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При создании объекта хеш функции возникла ошибка.");
    }
    // Вычисление криптографического хеша буфера.

      if(!CryptHashData(
          hHash,
          pbBuffer,
          dwBufferLen,
          0))
      {
           QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении хэша содержимого файла произошла ошибка.");
      }
      if(!CryptImportKey(
                  hProvSign,
                  pbKeyBlob,
                  dwBlobLen,
                  0,
                  0,
                  &hPubKeySign))
      {
          QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При импортировании открытого ключа произошла ошибка.");
      }
      // Проверка цифровой подписи.
      if(!CryptVerifySignature(
                  hHash,
                  pbSignature,
                  dwSigLen,
                  hPubKeySign,
                  NULL,
                  0))
      {
          QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При проверке подписи произошла ошибка.");
      }
      else{
          QMessageBox::information(NULL,QObject::tr("Подпись верна"), "Подпись прошла проверку.");
      }
      if(hHash)
          CryptDestroyHash(hHash);

}



bool MainWindow::crypt(bool type)
{
        FILE *content=NULL;              // Исходный файл
        FILE *Crypt=NULL;              // Зашифрованный файл

        BYTE pbContent[BLOCK_LENGTH] = { 0 };	// Указатель на содержимое исходного файла
        DWORD cbContent = 0;					// Длина содержимого
        DWORD bufLen = sizeof(pbContent);       // Размер буфера
        QString startvector;

        if(ui->leVector->text() == "")
        { // если фраза не указана, то задаем ей значение по умолчанию отличное от 0
            //это фажно, так как при передаче 0 в качестве аргумента, IV будет случайным
            startvector = "password";
        } else
        {
            startvector = ui->leVector->text();
        }

        //Задаем вектор инициализкации
        if(!CryptSetKeyParam(hSessionKey,KP_IV, (BYTE *)startvector.toLocal8Bit().data(),0))
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка установки вектора инициализации.");
            return 1;
        }

        //Открываем файл
        content = fopen(Filename.toLocal8Bit().data(), "r");
        if (!content){
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка открытия файла для шифрования.");
            return 1;
        }
        if (type)
        {
            //Открываем/создаем файл для результата
         Crypt = fopen((Filename + ".enc").toLocal8Bit().data(), "wb");
         if (!Crypt){
              QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка открытия файла для результата шифрования.");
               return 1;
         }
            do
            {
                // Берем блок для шифрования
                memset(pbContent, 0, sizeof(pbContent));
                cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH , content);
                pbContent[cbContent] = '\0';

                if (cbContent)
                {
                    // Проверяем последний ли это блок
                    BOOL bFinal = feof(content);
                    // Зашифрованние прочитанного блока на сессионном ключе.
                    if (CryptEncrypt(hSessionKey, 0, bFinal, 0, (BYTE*)pbContent, &cbContent, bufLen))
                    {
                        // Запись зашифрованного блока в файл.
                        if (!fwrite(pbContent, 1, cbContent, Crypt))
                        {
                            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка записи зашифрованного блока.");
                            fclose(Crypt);
                            fclose(content);
                            return 1;
                        }
                    }
                    else
                    {
                        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка при шифровании блока.");
                        fclose(Crypt);
                        fclose(content);
                        return 1;
                    }
                }
                else
                {
                    QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка чтения блока из файла.");
                    fclose(Crypt);
                    fclose(content);
                    return 1;
                }
            } while (!feof(content));   // Выполняем пока не дойдем до конца файла

            fclose(Crypt);
            fclose(content);
        } else
        {

        Crypt = fopen((Filename + ".dec").toLocal8Bit().data(), "wb");
        if (!Crypt){
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка открытия файла для результата дешифрования.");
            return 1;
        }

        do
        {
            memset(pbContent, 0, sizeof(pbContent));
            cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH , content);
            pbContent[cbContent] = '\0';

            if (cbContent)
            {
                BOOL bFinal = feof(content);
                // Дешифроние прочитанного блока на сессионном ключе.
                if (CryptDecrypt(hSessionKey, 0, bFinal, 0, (BYTE*)pbContent, &cbContent))
                {
                    // Запись дешифрованного блока в файл.
                    if (!fwrite(pbContent, 1, cbContent, Crypt))
                    {
                        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка записи дешифрованного блока.");
                        fclose(Crypt);
                        fclose(content);
                        return 1;
                    }
                }
                else
                {
                    QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка при дешифровании блока.");
                    fclose(Crypt);
                    fclose(content);
                    return 1;
                }
            }
            else
            {
                QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка чтения блока из файла.");
                fclose(Crypt);
                fclose(content);
                return 1;
            }
        } while (!feof(content));

        fclose(Crypt);
        fclose(content);
    }
        return 0;
}


