#pragma once
#include <QWidget>
#include <functional>

#include "core/FileGuardCore.h"

class QComboBox;
class QLabel;
class QLineEdit;

class LoginWindow : public QWidget {
public:
    LoginWindow(fg::FileGuardCore& core, std::function<void(const fg::User&)> onLogin);

private:
    void doLogin();
    void doRegister();
    fg::FileGuardCore& core_;
    std::function<void(const fg::User&)> onLogin_;
    QLineEdit* user_;
    QLineEdit* pass_;
    QComboBox* role_;
    QLabel* msg_;
};
