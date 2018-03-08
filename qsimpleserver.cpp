#include "qsimpleserver.h"

QSimpleServer::QSimpleServer(QObject *parent) :
    QTcpServer(parent)
{

//--------------config-data------------------------------------------------------


            readConfig(lst);

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
               //    return 1;
            }else{
                  //     QStringList lst = db.tables();
                  //     foreach (QString str, lst) {
                  //     qDebug() << QTime::currentTime().toString() + ": " + str;
                  // }

                    qDebug() << "Connect to database.... ok";
        }


//----------------------PATTERNS-------------------------------------------------



          //map["key"] = "value";       //  write to map
          //map.insert("key", "value");

          //map.value("key");           // reading from map: returns value by key


            int i = 25;  // from line 25 begin patterns

            while(lst[i] != "#")
            {
                QString temp(lst[i]);
                QString key;
                QString val;
                for(auto &c: lst[i])
                {
                    key += c;

                    if(c == ':' || c == '!')
                    {
                        break;
                    }
                }

                val = temp.mid(key.length(), temp.length() - key.length());

                map.insert(key, val);


                ++i;

            }




//----------------------TCP-SERVER-----------------------------------------------


          if(listen(QHostAddress::Any, portTCP.toInt()))
          {
              qDebug() << "Listening...";
          }else
              qDebug() << "Error while starting: " + errorString();


}

void QSimpleServer::incomingConnection(int handle)
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

    qDebug()<<"waiting for encryption";


    if(!socket->waitForEncrypted()){

        qDebug() << socket->errorString();

        return;
    }

    qDebug() << "Connection is encrypted.";


    connect(socket, SIGNAL(readyRead()), this, SLOT(onReadyRead()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(onDisconnected()));

}


void QSimpleServer::readConfig(QStringList &line)
{
    QFile in("config");
    if (!in.open(QIODevice::ReadOnly | QIODevice::Text))
     {
          qDebug() << "Unable to read the configuration file. \n Firstly, check the location.";
          //return;
     }else{
        qDebug() << "Open configuration file.... ok";
    }
     while (!in.atEnd()) {
         QString temp = in.readLine();
         QString str;
         for(auto &c:temp)
         {
             if(c == '\n')
                     break;
             str += c;
         }
         line.push_back(str);
     }
}


void QSimpleServer::onReadyRead()
{
    QSslSocket* socket = qobject_cast<QSslSocket*> (sender());


    QString message(socket->readAll());

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

        if(key.mid(0, 4) == "show")
            queryToSql(attribute, key, answ);
        else if(key.mid(0, 3) == "set")
            updateSql(id, key, attribute);
        else
            queryToSql(id, key, answ);

        //socket->write(answ.toLatin1());

        socket->write(answ.toUtf8());

    }
    else
        socket->write("denied");

    socket->waitForBytesWritten();

    socket->disconnectFromHost();

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


        QSqlRecord rec = query.record();


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



}


bool QSimpleServer::chekAuth(const QString &id, const QString &pass)
{
    // Здесь выполняется запрос в базу, для проверки верен ли пароль для
    // данного id/имени
    // Если id это isDigit - то WHERE id = ...,
    // если же id это isLetter - то соответственно WHERE name = ...

    if(id[0].isDigit()){
    query.exec("SELECT passwd, AES_DECRYPT(passwd, 'key')"
               " AS PASSWORD FROM users WHERE id=" + id);
    }else{
        query.exec("SELECT passwd, AES_DECRYPT(passwd, 'key')"
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


void QSimpleServer::updateSql(const QString &id, const QString &key, const QString arg)
{
    // id - кто клиент
    // que - текст запроса
    // arg - аргумент (например: UPDATE users SET next_paket=7(arg) WHERE id=12855(id)) (que)

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

    for(auto &c:t_param)      // param    'next_paket'
    {
        if(c == ' ')
            break;
        param += c;
    }



    quest += ' ' + param + "=" + arg + ' ';





    if(id[0].isDigit())
    {
        query.exec(quest + "WHERE id=" + id);
    }
    else
    {
        query.exec(quest + "WHERE name='" + id + "'");
    }


}


void QSimpleServer::onDisconnected()
{
    QSslSocket* socket = qobject_cast<QSslSocket*> (sender());
    socket->close();
    socket->deleteLater();
}




























