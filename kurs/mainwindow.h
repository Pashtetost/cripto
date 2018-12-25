#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QFileDialog>
#include <QDebug>

#include <fstream>

#include <windows.h>
#include <wincrypt.h>

#define MAX_CONTAINER_NAME_LEN 260  // максимальная длинна имени ключевого контейнера
#define BLOCK_LENGTH 4096

// Из-за того, что cpcspi.dll не подключается нормально сами объявим типы криптопровайдеров Крипто Про основываясь на записях реестров
#define PROV_GOST_2001_DH 75    // провайдер использует алгоритм ГОСТ Р 34.10-2001
#define PROV_GOST_2012_256 80   // провайдер использует алгоритм ГОСТ Р 34.10-2012 длины 256 бит (длина открытого ключа 512 бит)
#define PROV_GOST_2012_512 81   // провайдер использует алгоритм ГОСТ Р 34.10-2012 длины 512 бит (длина открытого ключа 1024 бит)

//По аналогичной причине
#define CALG_GR3411_2012_256 32801  // алгоритм для хэширования
#define CALG_G28147 26142           // алгоритм шифрования

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool crypt(bool type); //функция шифрования\дешифрования
    HCRYPTPROV hProvCrypt;        // Дескриптор контекста  критографического провайдера подпись.
    HCRYPTPROV hProvSign;         //Дескриптор контекста  критографического провайдера шифрование.

    HCRYPTKEY hKeySign;                 // Дескриптор ключеваой пары подписи
    HCRYPTKEY hPubKeySign;              // Дескриптор открытого ключа подписи

    HCRYPTKEY hKeyCrypt;                 // Дескриптор ключеваой пары подписи
    HCRYPTKEY hPubKeyCrypt;              // Дескриптор открытого ключа подписи

    HCRYPTKEY hSessionKey;          // Дескриптор сессионного ключа
    QString Filename;

    HCRYPTHASH hHash;               // Дискриптор Хэша
    BYTE *pbKeyBlob;// экспортированный открытый ключ

private slots:
    void on_pbCon_clicked();

    void on_pbCon_2_clicked();

    void on_pbFile_clicked();

    void on_pbEncrypt_clicked();

    void on_pbDecrypt_clicked();

    void on_pbSign_clicked();

    void on_pbCheck_clicked();

private:
    Ui::MainWindow *ui;
            // Дескриптор открытого/закрытого ключа.
};

#endif // MAINWINDOW_H
