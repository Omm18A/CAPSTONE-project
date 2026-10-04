#include "ui/LogsWindow.h"

#include <QPushButton>
#include <QVBoxLayout>

#include "ui/UiCommon.h"

LogsWindow::LogsWindow(fg::FileGuardCore& core, const fg::User& user, Mode mode, QWidget* parent)
    : QDialog(parent), core_(core), user_(user), mode_(mode) {
    const bool audit = mode == Mode::AuditLog;
    setWindowTitle(audit ? "FileGuard - Access Logs" : "FileGuard - Security Alerts");
    table_ = ui::makeTable(this, audit ? QStringList{"Timestamp (UTC)", "User", "File ID", "Action", "Result", "Details"}
                                       : QStringList{"Timestamp (UTC)", "User", "File ID", "Type", "Severity", "Details"});
    auto* btn = new QPushButton("Refresh");
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(table_); lay->addWidget(btn);
    connect(btn, &QPushButton::clicked, this, [this] { refresh(); });
    resize(900, 480);
    refresh();
}

void LogsWindow::refresh() {
    table_->setRowCount(0);
    if (mode_ == Mode::AuditLog) {
        for (auto& e : core_.audit.recent(user_, 500))
            ui::addRow(table_, {ui::q(e.timestamp), ui::q(e.username), ui::q(e.fileUuid), ui::q(e.action), ui::q(e.result), ui::q(e.details)});
    } else {
        for (auto& e : core_.security.recent(user_, 500))
            ui::addRow(table_, {ui::q(e.timestamp), ui::q(e.username), ui::q(e.fileUuid), ui::q(e.type), ui::q(e.severity), ui::q(e.details)});
    }
    table_->resizeColumnsToContents();
}
