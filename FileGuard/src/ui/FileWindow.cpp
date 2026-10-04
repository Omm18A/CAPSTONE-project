#include "ui/FileWindow.h"

#include <QApplication>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include "ui/UiCommon.h"

FileWindow::FileWindow(fg::FileGuardCore& core, const fg::User& user, QWidget* parent)
    : QDialog(parent), core_(core), user_(user) {
    setWindowTitle("FileGuard - My Files");
    table_ = ui::makeTable(this, {"File ID", "Filename", "Size", "Owner", "Your access", "Created (UTC)"});
    details_ = new QLabel("Select a file to see its details.");
    details_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    details_->setWordWrap(true);

    auto* reg = new QPushButton("Register file...");
    auto* open = new QPushButton("Open");
    auto* ver = new QPushButton("Verify integrity");
    auto* dl = new QPushButton("Download decrypted copy...");
    auto* exp = new QPushButton("Export .fguard package...");
    auto* pkg = new QPushButton("Open .fguard file...");
    auto* row = new QHBoxLayout;
    for (auto* b : {reg, open, ver, dl, exp, pkg}) row->addWidget(b);
    const bool canRegister = user.role == fg::Role::Owner || user.role == fg::Role::Admin;
    reg->setEnabled(canRegister);
    if (!canRegister) reg->setToolTip("Only OWNER accounts can register files.");

    auto* lay = new QVBoxLayout(this);
    lay->addWidget(table_); lay->addWidget(details_); lay->addLayout(row);
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this] { showDetails(); });
    connect(reg, &QPushButton::clicked, this, [this] { registerFile(); });
    connect(open, &QPushButton::clicked, this, [this] { openSelected(); });
    connect(ver, &QPushButton::clicked, this, [this] { verifySelected(); });
    connect(dl, &QPushButton::clicked, this, [this] { downloadSelected(); });
    connect(exp, &QPushButton::clicked, this, [this] { exportSelected(); });
    connect(pkg, &QPushButton::clicked, this, [this] { openPackage(); });
    resize(960, 520);
    refresh();
}

void FileWindow::refresh() {
    files_ = core_.files.listVisible(user_);
    table_->setRowCount(0);
    for (auto& f : files_) {
        auto e = core_.perms.effective(user_, f);
        ui::addRow(table_, {ui::q(f.uuid), ui::q(f.originalName), ui::humanSize(f.originalSize), ui::q(f.ownerName),
                            e ? (f.ownerId == user_.id ? QString("OWNER") : ui::q(fg::toString(*e))) : "-", ui::q(f.createdAt)});
    }
    table_->resizeColumnsToContents();
    showDetails();
}

const fg::FileRecord* FileWindow::selected() {
    int r = table_->currentRow();
    if (r < 0 || r >= static_cast<int>(files_.size())) { QMessageBox::information(this, "FileGuard", "Select a file first."); return nullptr; }
    return &files_[static_cast<size_t>(r)];
}

void FileWindow::showDetails() {
    int r = table_->currentRow();
    if (r < 0 || r >= static_cast<int>(files_.size())) { details_->setText("Select a file to see its details."); return; }
    const auto& f = files_[static_cast<size_t>(r)];
    details_->setText("File ID: " + ui::q(f.uuid) + "    Filename: " + ui::q(f.originalName) + "    Size: " + ui::humanSize(f.originalSize) +
                      "\nOriginal SHA-256: " + ui::q(f.originalHash) + "\nCreated: " + ui::q(f.createdAt) + " UTC    Owner: " + ui::q(f.ownerName) +
                      "\nProtection status: " + (f.status == "ACTIVE" ? "ACTIVE - AES-256-GCM encrypted .fguard package" : ui::q(f.status)));
}

void FileWindow::registerFile() {
    QString path = QFileDialog::getOpenFileName(this, "Select a file to protect");
    if (path.isEmpty()) return;
    fg::FileRecord rec;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    fg::Status st = core_.files.registerFile(user_, ui::s(path), rec);
    QApplication::restoreOverrideCursor();
    if (!st.ok()) { ui::showStatus(this, st); return; }
    QMessageBox::information(this, "File protected",
        "File ID: " + ui::q(rec.uuid) + "\nSHA-256: " + ui::q(rec.originalHash) + "\nProtected package: " + ui::q(rec.protectedPath));
    refresh();
}

void FileWindow::openSelected() { if (auto* f = selected()) openViewer(f->uuid); }

void FileWindow::openPackage() {
    QString path = QFileDialog::getOpenFileName(this, "Open a protected file", QString(), "FileGuard files (*.fguard)");
    if (!path.isEmpty()) openViewer(ui::s(path));
}

void FileWindow::openViewer(const std::string& idOrPath) {
    QDialog viewer(this);
    viewer.setWindowTitle("FileGuard - Protected File Viewer");
    auto* status = new QLabel("Authenticating...");
    auto* text = new QPlainTextEdit; text->setReadOnly(true);
    auto* lay = new QVBoxLayout(&viewer);
    lay->addWidget(status); lay->addWidget(text);
    viewer.resize(720, 520);
    viewer.show();

    fg::Bytes content; fg::FileRecord rec;
    fg::Status st = core_.files.open(user_, idOrPath, content, &rec, [&](const std::string& step) {
        status->setText(ui::q(step));
        QApplication::processEvents();
    });
    if (!st.ok()) {
        status->setText(QString::fromUtf8(st.code == fg::Err::IntegrityFailure || st.code == fg::Err::Corrupted ? "\xe2\x9a\xa0 Integrity violation detected" : "Access not granted"));
        viewer.hide();
        ui::showStatus(this, st);
        refresh();
        return;
    }
    status->setText(QString::fromUtf8("\xe2\x9c\x93 Integrity verified   |   ") + ui::q(rec.originalName) + "  (" + ui::humanSize(rec.originalSize) + ", owner " + ui::q(rec.ownerName) + ")");
    bool binary = false;
    for (uint8_t c : content) if (c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t')) { binary = true; break; }
    if (binary) text->setPlainText("[Binary content, " + ui::humanSize(content.size()) + " - no preview available.\nSave a copy with 'Download' if you hold DOWNLOAD permission.]");
    else text->setPlainText(QString::fromUtf8(reinterpret_cast<const char*>(content.data()), static_cast<int>(content.size() > 1048576 ? 1048576 : content.size())));
    fg::secureZero(content);
    viewer.hide();
    viewer.exec();
    text->clear();
    refresh();
}

void FileWindow::verifySelected() {
    auto* f = selected();
    if (!f) return;
    fg::Status st = core_.files.verify(user_, f->uuid);
    if (st.ok()) QMessageBox::information(this, "Integrity", QString::fromUtf8("\xe2\x9c\x93 Integrity verified"));
    else ui::showStatus(this, st);
}

void FileWindow::downloadSelected() {
    auto* f = selected();
    if (!f) return;
    QString dest = QFileDialog::getSaveFileName(this, "Save decrypted copy", ui::q(f->originalName));
    if (dest.isEmpty()) return;
    fg::Status st = core_.files.download(user_, f->uuid, ui::s(dest));
    if (st.ok()) QMessageBox::information(this, "Download", "Decrypted copy saved (mode 0600).");
    else ui::showStatus(this, st);
}

void FileWindow::exportSelected() {
    auto* f = selected();
    if (!f) return;
    QString dest = QFileDialog::getSaveFileName(this, "Export protected package", ui::q(f->uuid) + ".fguard", "FileGuard files (*.fguard)");
    if (dest.isEmpty()) return;
    fg::Status st = core_.files.exportPackage(user_, f->uuid, ui::s(dest));
    if (st.ok()) QMessageBox::information(this, "Export", "Package exported. Recipients still need an account and a grant to open it.");
    else ui::showStatus(this, st);
}
