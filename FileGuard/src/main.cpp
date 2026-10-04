// FileGuard Qt GUI entry point. Business rules live in fg::FileGuardCore.
#include <QApplication>
#include <QMessageBox>
#include <QTimer>
#include <memory>

#include "core/FileGuardCore.h"
#include "ui/DashboardWindow.h"
#include "ui/LoginWindow.h"
#include "ui/UiCommon.h"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    fg::FileGuardCore core;
    fg::Status st = core.init();
    if (!st.ok()) {
        QMessageBox::critical(nullptr, "FileGuard cannot start", ui::q(st.message));
        return 1;
    }
    std::unique_ptr<DashboardWindow> dash;
    LoginWindow* login = nullptr;
    login = new LoginWindow(core, [&](const fg::User& u) {
        dash = std::make_unique<DashboardWindow>(core, u, [&] {
            dash->hide();
            login->show();
            QTimer::singleShot(0, [&] { dash.reset(); });   // never delete a window from inside its own handler
        });
        login->hide();
        dash->show();
    });
    login->show();
    int rc = app.exec();
    dash.reset();
    delete login;
    return rc;
}
