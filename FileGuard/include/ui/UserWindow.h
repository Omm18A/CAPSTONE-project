#pragma once
#include <QDialog>

#include "core/FileGuardCore.h"

class QTableWidget;

// ADMIN-only user management: list, create (any role), enable/disable.
class UserWindow : public QDialog {
public:
    UserWindow(fg::FileGuardCore& core, const fg::User& admin, QWidget* parent = nullptr);

private:
    void refresh();
    void addUser();
    void toggle(bool enable);
    fg::FileGuardCore& core_;
    fg::User admin_;
    QTableWidget* table_;
};
