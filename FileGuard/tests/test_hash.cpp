#include "TestUtil.h"
#include "core/HashManager.h"
using namespace fg;

int main() {
    // NIST test vectors
    Bytes abc = {'a', 'b', 'c'};
    CHECK(HashManager::sha256Hex(abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(HashManager::sha256Hex(Bytes{}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    TempDir d;
    std::string p = writeFile(d.path + "/a.txt", "abc");
    Bytes dig;
    CHECK_OK(HashManager::sha256File(p, dig, 1024));
    CHECK(hexEncode(dig) == HashManager::sha256Hex(abc));            // streaming == in-memory

    writeFile(p, "abd");                                               // modification detected
    Bytes dig2;
    CHECK_OK(HashManager::sha256File(p, dig2, 1024));
    CHECK(!constantTimeEqual(dig, dig2));

    CHECK_CODE(HashManager::sha256File(d.path + "/missing", dig, 1024), Err::IoFailure);
    CHECK_CODE(HashManager::sha256File(p, dig, 2), Err::InvalidInput);  // size limit
    return finish("test_hash");
}
