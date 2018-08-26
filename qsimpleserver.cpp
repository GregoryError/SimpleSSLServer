#include "qsimpleserver.h"
#include <iostream>

QSimpleServer::QSimpleServer(QObject *parent) :
    QTcpServer(parent)
{


    now = QDateTime::currentDateTime();

    qDebug() << "Check the current time...." << now.toString("yyyy-MM-dd HH:MM:ss");


    //--------------config-data------------------------------------------------------


    bool record;
    if(readConfig(lst))
        record = true;
    else record = false;

    QString hostSQL = lst[4];     // SQL connectivity data
    QString usrNameSQL = lst[5];
    QString passSQL = lst[6];
    QString portSQL = lst[7];
    QString nameSQL = lst[8];
    portTCP = lst[13];            // TCP settings


    //----------------------SQL------------------------------------------------------

    db.setHostName(hostSQL);
    db.setUserName(usrNameSQL);
    db.setPassword(passSQL);
    db.setPort(portSQL.toInt());
    db.setDatabaseName(nameSQL);
    db.setConnectOptions("MYSQL_OPT_RECONNECT=TRUE;");


    if(!db.open() ) {
        qDebug() << QTime::currentTime().toString() + db.lastError().text();

        qDebug() << "Available drivers: ";
        QStringList lst = db.drivers();
        for(auto &c:lst)
        {
            qDebug() << c;
        }


    }else{
        //     QStringList lst = db.drivers();
        //     foreach (QString str, lst) {
        //     qDebug() << QTime::currentTime().toString() + ": " + str;
        // }

        qDebug() << "Connect to database.... ok";
    }


    //----------------------PATTERNS-------------------------------------------------



    if(record){
        int i = 25;  // from line 25 begin patterns

        while(lst[i] != "end")
        {
            QString temp(lst[i]);
            QString key;
            QString val;
            for(const auto &c: temp)
            {
                key += c;

                if(c == ':' || c == '!')
                {
                    break;
                }
            }

            val = temp.mid(key.length(), temp.length() - key.length());
            map.insert(key, val);
            // qDebug() << "Recorded: " + key + " = " + val;
            ++i;
        }
    }else
        qDebug() << "Can`t make a command set";


    //----------------------TCP-SERVER-----------------------------------------------

    if(listen(QHostAddress::Any, portTCP.toInt()))
        qDebug() << "Listening port " << portTCP.toInt() << "...";
    else qDebug() << "Error while starting: " + errorString();


}

void QSimpleServer::senderToClient(QSslSocket *socket, const QString &str)
{
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_9);
    out << quint16(0) << str;
    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));
    socket->write(arrBlock);
}



void QSimpleServer::incomingConnection(qintptr handle)
{
    QSslSocket* socket = new QSslSocket();

    if(!socket->setSocketDescriptor(handle)){
        qDebug() << errorString();
        return;
    }

    const QString serverCertPath("client1.pem");
    const QString serverKeyPath("client1.key");
    socket->setLocalCertificate(serverCertPath);
    socket->setPrivateKey(serverKeyPath, QSsl::Rsa, QSsl::Pem, "test");
    socket->startServerEncryption();

    qDebug() << "waiting for encryption";


    if(!socket->waitForEncrypted()){

        qDebug() << socket->errorString();

        return;
    }

    qDebug() << "Connection is encrypted.";


    connect(socket, SIGNAL(readyRead()), this, SLOT(onReadyRead()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(onDisconnected()));

}

void QSimpleServer::onReadyRead()
{
    QSslSocket* socket = qobject_cast<QSslSocket*> (sender());

    //QString message;
    //
    //QDataStream in(socket);
    //in.setVersion(QDataStream::Qt_5_9);
    //
    //for (;;)
    //{
    //    if (!m_nNextBlockSize)
    //    {
    //        if (socket->bytesAvailable() < sizeof(quint16))
    //        {
    //            break;
    //        }
    //        in >> m_nNextBlockSize;
    //    }
    //    if (socket->bytesAvailable() < m_nNextBlockSize)
    //    {
    //        break;
    //    }
    //    in >> message;
    //
    //    m_nNextBlockSize = 0;
    //}




    QString message(socket->readAll());


    //socket->close();


    //qDebug() << message;

    QString authData;

    for(auto &c:message)
    {
        if(c == ')')
            break;
        if(c != '(')
            authData += c;
    }

    QString id, pass;

    for(auto &c:authData)
    {
        if(c == '#')
        {
            auto logLen = id.length() + 1;
            pass = authData.mid(logLen, authData.length() - logLen);
            break;
        }
        id += c;
    }

    QString key;

    auto keySince = authData.length() + 2;

    QString onlyQuestion = message.mid(keySince);

    for(auto &c:onlyQuestion)
    {
        key += c;
        if(c == '!' || c == ':')
            break;
    }


    QString attribute = onlyQuestion.mid(key.length());


    // Now we have strings: 'id', 'pass', 'key', and possibly, 'attribute'



    // qDebug() << id;
    // qDebug() << pass;
    // qDebug() << key;
    // qDebug() << attribute;


    QString answ;


    if(chekAuth(id, pass)){


        QString result;


        if(key.mid(0, 17) == "requestTrustedPay")
        {
            injectTrustedPay(id, key, socket);

        }
        else if(key.mid(0, 4) == "show"){
            queryToSql(attribute, key, answ);
        }
        else if(key.mid(0, 3) == "set")
            updateSql(id, key, attribute);
        else if(key.mid(0, 3) == "ask")
        {
            if(key.mid(0, 12) == "askPayments!")
            {
                askSql(id, key, answ);
                //preparePayTable(answ);

            }else askSql(id, key, answ);

        }else queryToSql(id, key, answ);

        if(key.mid(0, 11) == "getAllData!")
        {

            QString planName;
            short i(0);

            for(auto& c:answ)
            {
                if(c == ' ')
                    ++i;
                if(i == 4 && c != ' ')
                    planName += c;
            }

            QString planStr;

            queryToSql(planName, "showPlan:", planStr);

            i = 0;

            for(auto &c:answ)
            {
                result += c;
                if(c == ' ')
                    ++i;
                if(i == 4)
                {
                    result += planStr;
                    break;
                }
            }

        }else result = answ;

        qDebug() << QDate::currentDate().toString()
                    + ", " + QTime::currentTime().toString()
                    + ": " + id + " asking: " + key;



        senderToClient(socket, (key + result).toUtf8());

        //socket->write((key + result).toUtf8());
        //socket->waitForBytesWritten();
        socket->disconnectFromHost();

    }else
    {
        senderToClient(socket, "denied");

        // socket->write("denied");

        //socket->waitForBytesWritten();

        socket->disconnectFromHost();
    }
}




void QSimpleServer::injectTrustedPay(const QString &id, const QString &key, QSslSocket *sckt)
{
    QString t_quest = map.value(key);


    //qDebug() << t_quest;

    QString quest, cash;

    // chekForTrustedPay! - is the key for checking is it possible to take trusted pay
    // its content: SELECT * FROM pays WHERE mid = AND time BETWEEN AND type IN (20,21,22)



    QString payDate_f, payDate;                 // узнаем дату платежа в текущем мсц, и переводим ее в unixtime

    queryToSql(id, "askPayDate!", payDate_f);

    for (auto &ch: payDate_f)                  // considering to use RegXeps
        if (ch.isDigit())
            payDate += ch;



    QString dateSince = now.toString(payDate + "/MM/yyyy");   // dd/MM/yyyy

    QDateTime t_Date = QDateTime::fromString(dateSince, "dd/MM/yyyy");

    unsigned long dateSinceInt = t_Date.toTime_t();

    dateSince = QString::number(t_Date.toTime_t());

    // слудующая дата снятия


    dateSinceInt += 2629743;

    QString dateTill = QString::number(dateSinceInt);

    QString checkStr(map.value("chekForTrustedPay!"));

    QString checkQuest;

    for (auto &ch:checkStr)
    {
        checkQuest += ch;
        if (checkQuest.right(7) == "BETWEEN")
        {
            checkQuest += " ";
            checkQuest += dateSince + " AND " + dateTill;
        }

        if (checkQuest.right(1) == '=')
        {
            checkQuest += " " + id;
        }

    }


    qDebug() << "checkQuest:" << checkQuest;

    query.exec(checkQuest);


    QSqlRecord payRec = query.record();


    if (payRec.isEmpty())
    {
        qDebug() << "Allowed to take a pay";
        return;
    }
    else
    {
        senderToClient(sckt, "PayDenied");
        qDebug() << "PayDenied";
        return;
    }







    // Cash:
    // SELECT paket FROM users WHERE id=23341   (59)
    // SELECT price FROM plans2 WHERE id=59    (330)
    // SELECT srvs FROM users WHERE id=23341  (3)


    // INSERT INTO pays (mid, cash, type, time, admin_id, admin_ip, office, bonus, reason, coment, category)
    // VALUES (a, b, c, d, e, f, g, h, i, j, k)


    // Должно произойти следущее:
    // INSERT INTO pays (mid, cash, type, time, admin_id, admin_ip, office, bonus, reason, coment, category)
    // VALUES (3281, 550.00, 21, 1529922389, 1, INET_ATON('192.168.7.25'), 1, 'y', ' Платеж создан 22.06.18 13:26', '', 1000)
    //
    // UPDATE users SET balance=balance+550.00 WHERE id=3281 LIMIT


}

void QSimpleServer::queryToSql(const QString& id, const QString &key, QString &answer)
{

    QString quest = map.value(key);

    //QSqlQuery query;

    if(id[0].isDigit())
    {
        query.exec(quest + " id=" + id);
    }
    else
    {
        query.exec(quest + " name='" + id + "'");
    }


    // QSqlRecord rec = query.record();


    short q(0);

    for(auto &c:quest)
    {
        if(c == ',')
            ++q;
    }
    ++q;

    short i(0);

    while (query.next()) {

        while(i != q)
        {
            answer += query.value(i).toString();
            answer += " ";
            ++i;
        }
    }
    i = 0;
    q = 0;
    //qDebug() << "answer: " + answer;

}


void QSimpleServer::askSql(const QString &ident, const QString &key, QString &answer)
{
    //qDebug() << "OK, this is a new code.";

    QString quest = map.value(key);

    query.exec(quest + ident);

    short row = query.size();
    short column = query.record().count();

    // qDebug() << "Строк: " << row << ", столбцов: " << column;



    QSqlQueryModel model;

    model.setQuery(quest + ident);


    if(model.lastError().isValid())
        qDebug() << model.lastError();


    QVector<QString> times_vct, cashes_vct, comments_vct;

    int i(0);
    int j(0);

    QString sqlRec;

    while (j != column)
    {
        while(i != row)
        {
            sqlRec += model.record(i).value(j).toString() + ' ';

            if(j == 0)
            {
                //  qDebug() << i << ": " << sqlRec;
                times_vct.push_back(sqlRec);
                sqlRec.clear();
            }

            if(j == 1)
            {
                // qDebug() << i << ": " << sqlRec;
                cashes_vct.push_back(sqlRec);
                sqlRec.clear();
            }

            if(j == 2)
            {
                //sqlRec += 'R';
                //  qDebug() << i << ": " << sqlRec;
                comments_vct.push_back(sqlRec);
                sqlRec.clear();
            }
            ++i;
        }

        i = 0;
        ++j;
    }



    for(auto &sstr:times_vct)
    {
        //qDebug() << sstr;
        answer += sstr;
    }

    answer += "t";

    for(auto &sstr:cashes_vct)
    {
        //qDebug() << str;
        answer += sstr;
    }

    answer += "$";

    //qDebug() << "Now comments_vct parsing: ";
    for(auto &sstr:comments_vct)
    {
        //qDebug() << sstr;
        answer += sstr + '~';

    }

    answer += "@";


    //qDebug() << "Next information will be sent: ";
    //qDebug() << answer;


}


bool QSimpleServer::readConfig(QStringList &line)
{
    QFile in("config");
    if (!in.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qDebug() << "Unable to read the configuration file. \nFirstly, check the location.";
        return false;
    }else{
        qDebug() << "Open configuration file.... ok";

        while (!in.atEnd()) {
            QString temp = in.readLine();
            QString str;
            for(auto &c:temp)
            {
                if(c == '\n' || c == '\t')
                    break;
                str += c;
            }
            line.push_back(str);
        }
    }
    return true;
}




void QSimpleServer::updateSql(const QString &id, const QString &key, const QString arg)
{
    // id - кто клиент
    // que - текст запроса
    // arg - аргумент (например: UPDATE users SET next_paket=7(arg) WHERE id=12855(id)) (que)
    // UPDATE users SET auth WHERE

    QString t_quest = map.value(key);

    QString quest;

    QString t_param, param;

    for(auto &c:t_quest)      // quest    'UPDATE users SET '
    {
        quest += c;
        if(quest.right(3) == "SET"){
            t_param = t_quest.mid(quest.length() + 1);
            break;
        }

    }

    // Now    t_param = "auth WHERE"
    //        quest = "UPDATE users SET"

    for(auto &c:t_param)      // param    'next_paket'
    {
        if(c == ' ')
            break;
        param += c;
    }

    quest += ' ' + param + "=" + arg + ' ';

    // UPDATE users SET auth=arg WHERE id=12345

    //quest += ' ' + param + "='" + arg + "' ";


    if(id[0].isDigit())
    {
        query.exec(quest + "WHERE id=" + id);
    }
    else
    {
        query.exec(quest + "WHERE name='" + id + "'");
    }


}


bool QSimpleServer::chekAuth(const QString &id, const QString &pass)
{
    // Здесь выполняется запрос в базу, для проверки верен ли пароль для
    // данного id/имени
    // Если id это isDigit - то WHERE id = ...,
    // если же id это isLetter - то соответственно WHERE name = ...

    if(id[0].isDigit()){
        query.exec("SELECT passwd, AES_DECRYPT(passwd, 'hardpass3')"
                   " AS PASSWORD FROM users WHERE id=" + id);
    }else{
        query.exec("SELECT passwd, AES_DECRYPT(passwd, 'hardpass3')"
                   " AS PASSWORD FROM users WHERE name='" + id + "'");
    }

    QString passwd;
    while (query.next()) {

        passwd = query.value(1).toString();
    }

    if(pass == passwd)
        return true;
    else return false;
}


void QSimpleServer::onDisconnected()
{
    QSslSocket* socket = qobject_cast<QSslSocket*> (sender());
    socket->close();
    socket->deleteLater();
}


























