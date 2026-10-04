#pragma once
#include <QDialog>
#include <vector>

#include "core/FileGuardCore.h"

class QLabel;
class QTableWidget;

// File registration, details, open (viewer), verify, download, export.
class FileWindow : public QDialog {
public:
    FileWindow(fg::FileGuardCore& core, const fg::User& user, QWidget* parent = nullptr);

private:
    void refresh();
    void showDetails();
    const fg::FileRecord* selected();
    void registerFile();
    void openSelected();
    void openPackage();
    void openViewer(const std::string& idOrPath);
    void verifySelected();
    void downloadSelected();
    void exportSelected();

    fg::FileGuardCore& core_;
    fg::User user_;
    std::vector<fg::FileRecord> files_;
    QTableWidget* table_;
    QLabel* details_;
};
