#include "qsimpleserver.h"

QSimpleServer::QSimpleServer(QObject *parent) :
    QTcpServer(parent)
{

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



    //map["key"] = "value";       //  write to map
    //map.insert("key", "value");

    //map.value("key");           // reading from map: returns value by key


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
        qDebug() << "Listening...";
    else qDebug() << "Error while starting: " + errorString();


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


        QString result;


        if(key.mid(0, 4) == "show"){
            queryToSql(attribute, key, answ);
        }
        else if(key.mid(0, 3) == "set")
            updateSql(id, key, attribute);
        else if(key.mid(0, 3) == "ask")
        {
            if(key.mid(0, 12) == "askPayments!")
            {
                askSql(id, key, answ);
                preparePayTable(answ);

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



        socket->write((key + result).toUtf8());
        socket->waitForBytesWritten();
        socket->disconnectFromHost();

    }else
    {
        socket->write("denied");

        socket->waitForBytesWritten();

        socket->disconnectFromHost();
    }

}

void QSimpleServer::askSql(const QString &ident, const QString &key, QString &answer)
{

    QString quest = map.value(key);

    query.exec(quest + ident);

    short row = query.size();                  //  + 1 WWWHHHYYYYYYYYYYYYYYYYY ????????
    short column = query.record().count();

    qDebug() << "Строк: " << row << ", столбцов: " << column;

    QSqlQueryModel model;

    model.setQuery(quest + ident);
    //model.setQuery(query);


    if(model.lastError().isValid())
        qDebug() << model.lastError();


    int i(0);
    int j(0);

    while(j != row)
    {

        answer += model.record(j).value(i).toString();
        if(j + 1 != row)
            answer += ' ';
        ++j;

    }

    answer += '#';
    ++i;
    j = 0;

    while(j != row)
    {
        answer += model.record(j).value(i).toString();
        if(j + 1 != row)
            answer += ' ';
        ++j;
    }

    answer += '#';
    ++i;
    j = 0;

    while(j != row)
    {
        answer += model.record(j).value(i).toString();
        if(j + 1 != row)
            answer += ' ';
        ++j;
    }



    // QSqlTableModel model;
    //     model.setTable("employee");
    //     model.select();
    //     int salary = model.record(4).value("salary").toInt();


}


void QSimpleServer::preparePayTable(QString &str)
{
    QString temp = str;
    // raf data without key
    // qDebug() << temp;

    QString dates, cashNcom, t_coment;
    QVector<QString> v_dates, v_cash, v_coment;

    int datesLenght(0);

    for(auto &c:temp)
    {
        if(c == ' ' || c == '#')
        {
            v_dates.push_back(dates);
            dates.clear();
        }

        ++datesLenght;
        if(c == '#')
            break;
        if(c != ' ' && c != '#')
            dates += c;

    }

    int cashlenght(0);

    cashNcom = temp.mid(datesLenght);
    cashNcom += '#';

    QString t_cash;

    for(auto &c:cashNcom)
    {
        if(c == ' ' || c == '#')
        {
            v_cash.push_back(t_cash);
            // qDebug() << t_cash;
            t_cash.clear();
        }
        ++cashlenght;
        if(c == '#')
            break;
        if(c != ' ' && c != '#')
            t_cash += c;
    }

    QString coment = temp.mid(datesLenght + cashlenght);

    for(auto &c:coment)
    {
        if(c == ' ' || c == '#')
        {
            v_coment.push_back(t_coment);
            // qDebug() << t_cash;
            t_cash.clear();
        }
        ++cashlenght;
        if(c == '#')
            break;
        if(c != ' ' && c != '#')
            t_coment += c;
    }


    std::reverse(std::begin(v_cash), std::end(v_cash));
    std::reverse(std::begin(v_dates), std::end(v_dates));
    std::reverse(std::begin(v_coment), std::end(v_coment));

    QString result;
    int v_i(0);

    for(auto &c:v_cash)
    {
        if(v_i == v_dates.size())
            break;

        result += v_dates[v_i] + "<br>" +
                v_coment[v_i] +
                " Сумма: " + c + "<br><br>";
        ++v_i;
    }

    str = result;
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

    for(auto &c:t_param)      // param    'next_paket'
    {
        if(c == ' ')
            break;
        param += c;
    }

    quest += ' ' + param + "=" + arg + ' ';
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





























