#ifndef QSIMPLESERVER_H
#define QSIMPLESERVER_H

#include <QtNetwork>
#include <QSqlDatabase>
#include <QSql>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSqlQueryModel>
#include <QSqlError>
#include <QSettings>
#include <QMap>
#include <QFile>
#include <QString>
#include <QStringList>
#include <fstream>
#include <QCoreApplication>
#include <QDataStream>
#include <QTime>
#include <QObject>
//#include <QTcpSocket>
#include <QSslSocket>
#include <QRegExp>
#include <iostream>

#include <QDateTime>



#include <QByteArray>
#include <QDataStream>

class QSimpleServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit QSimpleServer(QObject *parent = nullptr);

    QSslSocket* socket;
    quint16 m_nNextBlockSize;
    QString request;
    QStringList lst;
    QString portTCP;
    QMap<QString, QString> map;
    QMap<int, int> srvsMap;
    QSqlDatabase db = QSqlDatabase::addDatabase("QMYSQL");
    QSqlQuery query;
    QDateTime now;
    int calls;



    void senderToClient(QSslSocket *socket, const QString &str);

    void incomingConnection(qintptr handle);
    bool readConfig(QStringList &line);
    void queryToSql(const QString &id, const QString& quest, QString& answer);
    void askSql(const QString &ident, const QString& key, QString& answer);
    void updateSql(const QString &id, const QString& key, const QString arg);
    void injectTrustedPay(const QString &id, const QString& key, QString &result);
    bool chekAuth(const QString& id, const QString& pass);
    void showMsgs(const QString &id, QString &result);
    void insertMsg(const QString &id, const QString &txt);

public slots:
    void onReadyRead();
    void onDisconnected();
};

#endif // QSIMPLESERVER_H





































