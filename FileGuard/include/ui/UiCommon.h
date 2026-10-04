#pragma once
// Small Qt helpers shared by the GUI windows. The GUI contains no business logic:
// every action calls into fg::FileGuardCore, exactly like the CLI does.
#include <QAbstractItemView>
#include <QHeaderView>
#include <QMessageBox>
#include <QString>
#include <QStringList>
#include <QTableWidget>

#include "core/Common.h"

namespace ui {

inline QString q(const std::string& s) { return QString::fromUtf8(s.data(), static_cast<int>(s.size())); }
inline std::string s(const QString& v) { return v.toUtf8().toStdString(); }

inline QString humanSize(uint64_t n) {
    if (n >= 1048576) return QString::number(n / 1048576.0, 'f', 1) + " MiB";
    if (n >= 1024) return QString::number(n / 1024.0, 'f', 1) + " KiB";
    return QString::number(n) + " B";
}

inline QTableWidget* makeTable(QWidget* parent, const QStringList& headers) {
    auto* t = new QTableWidget(parent);
    t->setColumnCount(headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::SingleSelection);
    t->horizontalHeader()->setStretchLastSection(true);
    t->verticalHeader()->setVisible(false);
    return t;
}

inline void addRow(QTableWidget* t, const QStringList& cells) {
    int r = t->rowCount();
    t->insertRow(r);
    for (int c = 0; c < cells.size(); ++c) t->setItem(r, c, new QTableWidgetItem(cells[c]));
}

// Integrity problems get a distinct warning; everything else is a normal error.
inline void showStatus(QWidget* parent, const fg::Status& st) {
    if (st.code == fg::Err::IntegrityFailure || st.code == fg::Err::Corrupted)
        QMessageBox::warning(parent, "FileGuard - Security alert", QString::fromUtf8("\xe2\x9a\xa0 ") + q(st.message));
    else if (st.code == fg::Err::AccessDenied || st.code == fg::Err::AuthFailed || st.code == fg::Err::AccountLocked)
        QMessageBox::warning(parent, "FileGuard - Access denied", q(st.message));
    else
        QMessageBox::critical(parent, "FileGuard - Error", q(st.message));
}

}  // namespace ui
