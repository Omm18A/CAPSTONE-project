#pragma once
#include <QDialog>

#include "core/FileGuardCore.h"

class QTableWidget;

// Shows either the audit log or the security alerts, filtered by the viewer's rights.
class LogsWindow : public QDialog {
public:
    enum class Mode { AuditLog, SecurityAlerts };
    LogsWindow(fg::FileGuardCore& core, const fg::User& user, Mode mode, QWidget* parent = nullptr);

private:
    void refresh();
    fg::FileGuardCore& core_;
    fg::User user_;
    Mode mode_;
    QTableWidget* table_;
};
