#include <QCoreApplication>
#include "qsimpleserver.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QSimpleServer server;

    Q_UNUSED(server);

    return a.exec();
}

