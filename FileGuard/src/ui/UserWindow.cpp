#include "ui/UserWindow.h"

#include <QApplication>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include "ui/UiCommon.h"

UserWindow::UserWindow(fg::FileGuardCore& core, const fg::User& admin, QWidget* parent)
    : QDialog(parent), core_(core), admin_(admin) {
    setWindowTitle("FileGuard - Users");
    table_ = ui::makeTable(this, {"ID", "Username", "Role", "Status", "Created (UTC)"});
    auto* add = new QPushButton("Add user...");
    auto* dis = new QPushButton("Disable selected");
    auto* en = new QPushButton("Enable selected");
    auto* row = new QHBoxLayout;
    row->addWidget(add); row->addWidget(dis); row->addWidget(en); row->addStretch();
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(table_); lay->addLayout(row);
    connect(add, &QPushButton::clicked, this, [this] { addUser(); });
    connect(dis, &QPushButton::clicked, this, [this] { toggle(false); });
    connect(en, &QPushButton::clicked, this, [this] { toggle(true); });
    resize(640, 420);
    refresh();
}

void UserWindow::refresh() {
    table_->setRowCount(0);
    for (auto& u : core_.users.list())
        ui::addRow(table_, {QString::number(u.id), ui::q(u.username), ui::q(fg::toString(u.role)), ui::q(u.status), ui::q(u.createdAt)});
    table_->resizeColumnsToContents();
}

void UserWindow::addUser() {
    QDialog d(this);
    d.setWindowTitle("Add user");
    auto* name = new QLineEdit; auto* pw = new QLineEdit; pw->setEchoMode(QLineEdit::Password);
    auto* role = new QComboBox; role->addItems({"USER", "OWNER", "ADMIN"});
    auto* form = new QFormLayout(&d);
    form->addRow("Username", name); form->addRow("Password", pw); form->addRow("Role", role);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    form->addRow(bb);
    connect(bb, &QDialogButtonBox::accepted, &d, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    if (d.exec() != QDialog::Accepted) return;
    fg::Role r = fg::Role::User;
    fg::parseRole(ui::s(role->currentText()), r);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    fg::Status st = core_.users.registerUser(ui::s(name->text()), ui::s(pw->text()), r, &admin_);
    QApplication::restoreOverrideCursor();
    if (!st.ok()) ui::showStatus(this, st);
    refresh();
}

void UserWindow::toggle(bool enable) {
    int row = table_->currentRow();
    if (row < 0) { QMessageBox::information(this, "Users", "Select a user first."); return; }
    fg::Status st = core_.users.setActive(admin_, ui::s(table_->item(row, 1)->text()), enable);
    if (!st.ok()) ui::showStatus(this, st);
    refresh();
}
