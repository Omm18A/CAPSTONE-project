#include "TestUtil.h"
using namespace fg;

int main() {
    Fixture fx;
    FileRecord f = fx.registerDoc();
    auto& pm = fx.core.perms;

    CHECK(pm.check(fx.omm, f, Permission::Download));                    // owner: everything
    CHECK(!pm.check(fx.rahul, f, Permission::View));                     // stranger: nothing

    CHECK_OK(pm.grant(fx.omm, f, fx.rahul, Permission::Read));
    CHECK(pm.check(fx.rahul, f, Permission::View));
    CHECK(pm.check(fx.rahul, f, Permission::Read));
    CHECK(!pm.check(fx.rahul, f, Permission::Download));                 // hierarchy: READ < DOWNLOAD
    CHECK(!pm.check(fx.priya, f, Permission::View));                     // other users unaffected

    CHECK_OK(pm.grant(fx.omm, f, fx.rahul, Permission::View));           // downgrade via upsert
    CHECK(!pm.check(fx.rahul, f, Permission::Read));
    CHECK(pm.listForFile(f.id).size() == 1);

    CHECK_CODE(pm.grant(fx.rahul, f, fx.priya, Permission::View), Err::AccessDenied);   // non-owner can't share
    CHECK_CODE(pm.grant(fx.admin, f, fx.priya, Permission::View), Err::AccessDenied);   // admin isn't owner
    CHECK_CODE(pm.grant(fx.omm, f, fx.omm, Permission::View), Err::InvalidInput);       // self-share
    CHECK_CODE(pm.grant(fx.omm, f, fx.rahul, Permission::View, -1), Err::InvalidInput);

    // expiry
    CHECK_OK(pm.grant(fx.omm, f, fx.priya, Permission::Read, 7));
    CHECK(pm.check(fx.priya, f, Permission::Read));
    auto up = fx.core.db.prepare("UPDATE permissions SET expires_at='2000-01-01 00:00:00' WHERE user_id=?1");
    up.bindInt(1, fx.priya.id); CHECK(up.execute());
    CHECK(!pm.check(fx.priya, f, Permission::View));                     // expired -> denied

    // revocation
    CHECK_OK(pm.grant(fx.omm, f, fx.rahul, Permission::Download));
    CHECK(pm.check(fx.rahul, f, Permission::Download));
    CHECK_CODE(pm.revoke(fx.priya, f, fx.rahul), Err::AccessDenied);     // random user can't revoke
    CHECK_OK(pm.revoke(fx.omm, f, fx.rahul));
    CHECK(!pm.check(fx.rahul, f, Permission::View));                     // revoked -> denied
    CHECK_CODE(pm.revoke(fx.omm, f, fx.rahul), Err::NotFound);
    CHECK_OK(pm.grant(fx.omm, f, fx.rahul, Permission::View));
    CHECK_OK(pm.revoke(fx.admin, f, fx.rahul));                          // admin may revoke
    CHECK(fx.countAction("FILE_REVOKED") == 2);
    CHECK(fx.countAction("FILE_SHARED") >= 4);

    // disabled users lose access even if a grant exists
    CHECK_OK(pm.grant(fx.omm, f, fx.rahul, Permission::Read));
    CHECK_OK(fx.core.users.setActive(fx.admin, "Rahul", false));
    User disabled = *fx.core.users.findByName("Rahul");
    CHECK(!pm.check(disabled, f, Permission::View));

    Permission p; CHECK(!parsePermission("WRITE", p)); CHECK(parsePermission("READ", p));
    return finish("test_permissions");
}
