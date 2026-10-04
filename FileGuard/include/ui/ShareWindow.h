#pragma once
#include <QDialog>
#include <vector>

#include "core/FileGuardCore.h"

class QComboBox;
class QSpinBox;
class QTableWidget;

// Owner workflow: select file -> select user -> select permission -> share; revoke from the grant list.
class ShareWindow : public QDialog {
public:
    ShareWindow(fg::FileGuardCore& core, const fg::User& owner, QWidget* parent = nullptr);

private:
    void refreshGrants();
    void share();
    void revoke();
    fg::FileGuardCore& core_;
    fg::User owner_;
    std::vector<fg::FileRecord> owned_;
    QComboBox *fileBox_, *userBox_, *permBox_;
    QSpinBox* days_;
    QTableWidget* grants_;
};
