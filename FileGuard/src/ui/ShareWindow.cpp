#include "ui/ShareWindow.h"

#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include "ui/UiCommon.h"

ShareWindow::ShareWindow(fg::FileGuardCore& core, const fg::User& owner, QWidget* parent)
    : QDialog(parent), core_(core), owner_(owner) {
    setWindowTitle("FileGuard - Share File");
    fileBox_ = new QComboBox; userBox_ = new QComboBox; permBox_ = new QComboBox;
    permBox_->addItems({"VIEW", "READ", "DOWNLOAD"});
    permBox_->setCurrentText("READ");
    permBox_->setToolTip("VIEW: metadata + integrity check\nREAD: view decrypted content in FileGuard\nDOWNLOAD: also save a decrypted copy");
    days_ = new QSpinBox; days_->setRange(0, 3650); days_->setSpecialValueText("Never"); days_->setSuffix(" days");

    for (auto& f : core_.files.listVisible(owner_))
        if (f.ownerId == owner_.id) { owned_.push_back(f); fileBox_->addItem(ui::q(f.uuid + "  -  " + f.originalName)); }
    for (auto& u : core_.users.list())
        if (u.id != owner_.id && u.status == "ACTIVE") userBox_->addItem(ui::q(u.username));

    auto* form = new QFormLayout;
    form->addRow("File", fileBox_); form->addRow("User", userBox_);
    form->addRow("Permission", permBox_); form->addRow("Expires after", days_);
    auto* shareBtn = new QPushButton("Share");
    auto* revokeBtn = new QPushButton("Revoke selected access");
    auto* row = new QHBoxLayout; row->addWidget(shareBtn); row->addWidget(revokeBtn);
    grants_ = ui::makeTable(this, {"User", "Permission", "Granted (UTC)", "Expires (UTC)"});

    auto* lay = new QVBoxLayout(this);
    if (owned_.empty()) lay->addWidget(new QLabel("You do not own any protected files yet. Register one under 'My Files'."));
    lay->addLayout(form); lay->addLayout(row);
    lay->addWidget(new QLabel("Current access to the selected file:")); lay->addWidget(grants_);
    shareBtn->setEnabled(!owned_.empty()); revokeBtn->setEnabled(!owned_.empty());
    connect(fileBox_, &QComboBox::currentIndexChanged, this, [this] { refreshGrants(); });
    connect(shareBtn, &QPushButton::clicked, this, [this] { share(); });
    connect(revokeBtn, &QPushButton::clicked, this, [this] { revoke(); });
    resize(620, 520);
    refreshGrants();
}

void ShareWindow::refreshGrants() {
    grants_->setRowCount(0);
    int i = fileBox_->currentIndex();
    if (i < 0 || i >= static_cast<int>(owned_.size())) return;
    for (auto& g : core_.perms.listForFile(owned_[static_cast<size_t>(i)].id))
        ui::addRow(grants_, {ui::q(g.username), ui::q(g.permission), ui::q(g.createdAt), g.expiresAt.empty() ? QString("never") : ui::q(g.expiresAt)});
    grants_->resizeColumnsToContents();
}

void ShareWindow::share() {
    int i = fileBox_->currentIndex();
    if (i < 0 || userBox_->currentIndex() < 0) { QMessageBox::information(this, "Share", "Select a file and a user."); return; }
    fg::Permission p = fg::Permission::Read;
    fg::parsePermission(ui::s(permBox_->currentText()), p);
    fg::Status st = core_.files.share(owner_, owned_[static_cast<size_t>(i)].uuid, ui::s(userBox_->currentText()), p, days_->value());
    if (!st.ok()) ui::showStatus(this, st);
    refreshGrants();
}

void ShareWindow::revoke() {
    int i = fileBox_->currentIndex(), r = grants_->currentRow();
    if (i < 0 || r < 0) { QMessageBox::information(this, "Revoke", "Select a user in the access list first."); return; }
    fg::Status st = core_.files.revoke(owner_, owned_[static_cast<size_t>(i)].uuid, ui::s(grants_->item(r, 0)->text()));
    if (!st.ok()) ui::showStatus(this, st);
    refreshGrants();
}
