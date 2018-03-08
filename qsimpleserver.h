#ifndef QSIMPLESERVER_H
#define QSIMPLESERVER_H

#include <QTcpServer>
#include <QSslSocket>
#include <QDebug>
#include <QDateTime>
#include <QDataStream>


#include <QtNetwork>
#include <QSqlDatabase>
#include <QSql>
#include <QSqlQuery>
#include <QSqlRecord>
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


class QSimpleServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit QSimpleServer(QObject *parent = 0);


    quint16 m_nNextBlockSize;
    QString request;
    QStringList lst;
    QString portTCP;
    QMap<QString, QString> map;
    QSqlDatabase db = QSqlDatabase::addDatabase("QMYSQL");
    QSqlQuery query;


    void incomingConnection(int handle);
    void readConfig(QStringList &line);
    void queryToSql(const QString &id, const QString& quest, QString& answer);
    void updateSql(const QString &id, const QString& key, const QString arg);
    bool chekAuth(const QString& id, const QString& pass);

public slots:
    void onReadyRead();
    void onDisconnected();
};

#endif // QSIMPLESERVER_H
