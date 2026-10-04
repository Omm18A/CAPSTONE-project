#include "ui/DashboardWindow.h"

#include <QDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QFontDatabase>
#include <QVBoxLayout>

#include "core/LinuxSystemManager.h"
#include "ui/FileWindow.h"
#include "ui/LogsWindow.h"
#include "ui/ShareWindow.h"
#include "ui/UiCommon.h"
#include "ui/UserWindow.h"

namespace {
QLabel* statBox(QHBoxLayout* row, const QString& caption) {
    auto* box = new QVBoxLayout;
    auto* num = new QLabel("0");
    num->setAlignment(Qt::AlignCenter);
    num->setStyleSheet("font-size:28px;font-weight:bold;");
    auto* cap = new QLabel(caption);
    cap->setAlignment(Qt::AlignCenter);
    box->addWidget(num); box->addWidget(cap);
    row->addLayout(box);
    return num;
}
}  // namespace

DashboardWindow::DashboardWindow(fg::FileGuardCore& core, const fg::User& user, std::function<void()> onLogout)
    : core_(core), user_(user), onLogout_(std::move(onLogout)) {
    setWindowTitle("FileGuard - Dashboard");
    auto* central = new QWidget;
    auto* lay = new QVBoxLayout(central);
    auto* title = new QLabel("<h1>FILEGUARD</h1>");
    title->setAlignment(Qt::AlignCenter);
    lay->addWidget(title);
    lay->addWidget(new QLabel("<h3>Welcome, " + ui::q(user.username).toHtmlEscaped() + "  <small>(" + ui::q(fg::toString(user.role)) + ")</small></h3>"));

    auto* stats = new QHBoxLayout;
    protectedLbl_ = statBox(stats, "Protected files");
    sharedLbl_ = statBox(stats, "Shared with me");
    attemptsLbl_ = statBox(stats, "Logged events");
    alertsLbl_ = statBox(stats, "Security alerts");
    lay->addLayout(stats);

    auto* row = new QHBoxLayout;
    auto addBtn = [&](const QString& text, std::function<void()> fn) {
        auto* b = new QPushButton(text);
        row->addWidget(b);
        connect(b, &QPushButton::clicked, this, [this, fn] { fn(); refresh(); });
    };
    addBtn("My Files", [this] { FileWindow(core_, user_, this).exec(); });
    addBtn("Share File", [this] { ShareWindow(core_, user_, this).exec(); });
    if (user_.role == fg::Role::Admin) addBtn("Users", [this] { UserWindow(core_, user_, this).exec(); });
    addBtn("Access Logs", [this] { LogsWindow(core_, user_, LogsWindow::Mode::AuditLog, this).exec(); });
    addBtn("Security Alerts", [this] { LogsWindow(core_, user_, LogsWindow::Mode::SecurityAlerts, this).exec(); });
    addBtn("Settings / System Info", [this] { showSystemInfo(); });
    auto* out = new QPushButton("Logout");
    row->addWidget(out);
    connect(out, &QPushButton::clicked, this, [this] { onLogout_(); });
    lay->addLayout(row);

    lay->addWidget(new QLabel("Recent access events"));
    recent_ = ui::makeTable(this, {"Timestamp (UTC)", "User", "File ID", "Action", "Result"});
    lay->addWidget(recent_);
    setCentralWidget(central);
    resize(900, 600);
    refresh();
}

void DashboardWindow::refresh() {
    protectedLbl_->setText(QString::number(core_.files.countOwned(user_)));
    sharedLbl_->setText(QString::number(core_.files.countSharedWith(user_)));
    attemptsLbl_->setText(QString::number(core_.audit.count(user_)));
    alertsLbl_->setText(QString::number(core_.security.count(user_)));
    recent_->setRowCount(0);
    for (auto& e : core_.audit.recent(user_, 12))
        ui::addRow(recent_, {ui::q(e.timestamp), ui::q(e.username), ui::q(e.fileUuid), ui::q(e.action), ui::q(e.result)});
    recent_->resizeColumnsToContents();
}

void DashboardWindow::showSystemInfo() {
    QDialog d(this);
    d.setWindowTitle("System information (read from uname, /proc, /sys, statvfs)");
    auto* text = new QPlainTextEdit(ui::q(fg::LinuxSystemManager::format(fg::LinuxSystemManager::gather(core_.config.baseDir()))));
    text->setReadOnly(true);
    text->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    auto* lay = new QVBoxLayout(&d);
    lay->addWidget(text);
    d.resize(720, 420);
    d.exec();
}
