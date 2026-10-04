#include "ui/LoginWindow.h"

#include <QApplication>
#include <QComboBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include "ui/UiCommon.h"

LoginWindow::LoginWindow(fg::FileGuardCore& core, std::function<void(const fg::User&)> onLogin)
    : core_(core), onLogin_(std::move(onLogin)) {
    setWindowTitle("FileGuard - Login");
    auto* title = new QLabel("<h1>FILEGUARD</h1><p>Secure file distribution, access control and audit logging</p>");
    title->setAlignment(Qt::AlignCenter);
    user_ = new QLineEdit; pass_ = new QLineEdit;
    pass_->setEchoMode(QLineEdit::Password);
    role_ = new QComboBox;
    role_->addItems({"OWNER", "USER"});
    msg_ = new QLabel;
    msg_->setWordWrap(true);

    auto* form = new QFormLayout;
    form->addRow("Username", user_);
    form->addRow("Password", pass_);
    form->addRow("Register as", role_);
    auto* loginBtn = new QPushButton("Login");
    auto* regBtn = new QPushButton("Register");
    auto* row = new QHBoxLayout;
    row->addWidget(loginBtn); row->addWidget(regBtn);

    auto* lay = new QVBoxLayout(this);
    lay->addWidget(title); lay->addLayout(form); lay->addLayout(row); lay->addWidget(msg_);
    if (core_.users.count() == 0)
        msg_->setText("No accounts exist yet. The first account you register becomes the ADMIN (password: 8+ characters).");

    connect(loginBtn, &QPushButton::clicked, this, [this] { doLogin(); });
    connect(regBtn, &QPushButton::clicked, this, [this] { doRegister(); });
    connect(pass_, &QLineEdit::returnPressed, this, [this] { doLogin(); });
    resize(420, 320);
}

void LoginWindow::doLogin() {
    QApplication::setOverrideCursor(Qt::WaitCursor);   // PBKDF2 is deliberately slow
    fg::LoginResult r = core_.auth.login(ui::s(user_->text()), ui::s(pass_->text()));
    QApplication::restoreOverrideCursor();
    pass_->clear();
    if (!r.status.ok()) { msg_->setText("<span style='color:#b00020'>" + ui::q(r.status.message).toHtmlEscaped() + "</span>"); return; }
    msg_->clear();
    user_->clear();
    onLogin_(*r.user);
}

void LoginWindow::doRegister() {
    fg::Role role = role_->currentText() == "OWNER" ? fg::Role::Owner : fg::Role::User;
    const bool bootstrap = core_.users.count() == 0;
    if (bootstrap) role = fg::Role::Admin;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    fg::Status st = core_.users.registerUser(ui::s(user_->text()), ui::s(pass_->text()), role, nullptr);
    QApplication::restoreOverrideCursor();
    pass_->clear();
    if (!st.ok()) { msg_->setText("<span style='color:#b00020'>" + ui::q(st.message).toHtmlEscaped() + "</span>"); return; }
    msg_->setText(bootstrap ? "ADMIN account created. You can now log in." : "Account created. You can now log in.");
}
