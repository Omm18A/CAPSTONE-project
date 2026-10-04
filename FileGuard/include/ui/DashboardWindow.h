#pragma once
#include <QMainWindow>
#include <functional>

#include "core/FileGuardCore.h"

class QLabel;
class QTableWidget;

class DashboardWindow : public QMainWindow {
public:
    DashboardWindow(fg::FileGuardCore& core, const fg::User& user, std::function<void()> onLogout);

private:
    void refresh();
    void showSystemInfo();
    fg::FileGuardCore& core_;
    fg::User user_;
    std::function<void()> onLogout_;
    QLabel *protectedLbl_, *sharedLbl_, *attemptsLbl_, *alertsLbl_;
    QTableWidget* recent_;
};
