#include "TestUtil.h"
using namespace fg;

int main() {
    Fixture fx;
    auto& a = fx.core.auth;

    auto ok = a.login("Omm", "ommpass123");
    CHECK_OK(ok.status);
    CHECK(ok.user && ok.user->username == "Omm" && ok.user->role == Role::Owner);

    auto wrong = a.login("Omm", "nope-nope-1");
    CHECK_CODE(wrong.status, Err::AuthFailed);
    CHECK(!wrong.user);
    auto unknown = a.login("Ghost", "whatever123");
    CHECK_CODE(unknown.status, Err::AuthFailed);
    CHECK(wrong.status.message == unknown.status.message);               // no user enumeration

    // passwords are never stored in clear; salts are unique
    auto st = fx.core.db.prepare("SELECT password_hash,salt FROM users WHERE username IN ('Rahul','Priya') ORDER BY id");
    std::string h1, s1, hh2, s2;
    CHECK(st.next()); h1 = st.text(0); s1 = st.text(1);
    CHECK(st.next()); hh2 = st.text(0); s2 = st.text(1);
    CHECK(h1.find("rahulpass1") == std::string::npos && h1.size() == 64 && s1.size() == 32);
    CHECK(s1 != s2);
    auto same1 = fx.core.users.registerUser("Same1", "identicalpw1", Role::User, nullptr);
    auto same2 = fx.core.users.registerUser("Same2", "identicalpw1", Role::User, nullptr);
    CHECK_OK(same1); CHECK_OK(same2);
    auto st2 = fx.core.db.prepare("SELECT password_hash FROM users WHERE username IN ('Same1','Same2')");
    st2.next(); std::string x = st2.text(0); st2.next();
    CHECK(x != st2.text(0));                                             // same password, different hash

    // registration rules
    CHECK_CODE(fx.core.users.registerUser("Omm", "anotherpass1", Role::User, nullptr), Err::InvalidInput);  // duplicate
    CHECK_CODE(fx.core.users.registerUser("ab", "validpass1", Role::User, nullptr), Err::InvalidInput);     // short name
    CHECK_CODE(fx.core.users.registerUser("bad name", "validpass1", Role::User, nullptr), Err::InvalidInput);
    CHECK_CODE(fx.core.users.registerUser("Weak", "short", Role::User, nullptr), Err::InvalidInput);
    CHECK_CODE(fx.core.users.registerUser("Evil", "validpass1", Role::Admin, nullptr), Err::AccessDenied);  // no self-promotion
    CHECK_CODE(fx.core.users.registerUser("Evil2", "validpass1", Role::Admin, &fx.rahul), Err::AccessDenied);
    CHECK_OK(fx.core.users.registerUser("Admin2", "validpass1", Role::Admin, &fx.admin));

    // disabled users cannot log in
    CHECK_CODE(fx.core.users.setActive(fx.rahul, "Priya", false), Err::AccessDenied);                       // not admin
    CHECK_OK(fx.core.users.setActive(fx.admin, "Priya", false));
    CHECK_CODE(a.login("Priya", "priyapass1").status, Err::AuthFailed);
    CHECK_OK(fx.core.users.setActive(fx.admin, "Priya", true));
    CHECK_OK(a.login("Priya", "priyapass1").status);

    // brute force: lockout after 5 failures, even the right password is refused
    for (int i = 0; i < AuthenticationManager::kMaxFailures; ++i) CHECK_CODE(a.login("Rahul", "guess" + std::to_string(i) + "xx").status, Err::AuthFailed);
    CHECK_CODE(a.login("Rahul", "rahulpass1").status, Err::AccountLocked);
    CHECK(fx.countEvents("REPEATED_LOGIN_FAILURE") == 1);
    CHECK(fx.countAction("LOGIN_FAILURE") >= 6);
    CHECK(fx.countAction("LOGIN_SUCCESS") >= 2);

    // fresh store: first account must be ADMIN
    TempDir h2; FileGuardCore c2(h2.path, "/nonexistent");
    CHECK_OK(c2.init());
    CHECK_CODE(c2.users.registerUser("First", "validpass1", Role::Owner, nullptr), Err::InvalidInput);
    CHECK_OK(c2.users.registerUser("First", "validpass1", Role::Admin, nullptr));
    return finish("test_authentication");
}
