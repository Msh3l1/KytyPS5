#include "common/abi.h"
#include "common/emulatorConfig.h"
#include "libs/errno.h"
#include "libs/network.h"
#include "loader/symbolDatabase.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

namespace Libs {
void InitNet_1(Loader::SymbolDatabase *symbols);
void InitVrTracker2_1(Loader::SymbolDatabase *symbols);
namespace LibNet {
void InitNet_1_Net(Loader::SymbolDatabase *symbols);
} // namespace LibNet
} // namespace Libs

namespace {

namespace Network = Libs::Network;
using Network::Net::NetResolverInfo;

using StartNtoa = int(KYTY_SYSV_ABI *)(int, const char *, uint32_t *, int, int,
                                       int);
using StartNtoaMultipleRecords = int(KYTY_SYSV_ABI *)(int, const char *,
                                                      NetResolverInfo *, int,
                                                      int, int);

class NetResolverTest : public testing::Test {
protected:
  void SetUp() override {
    Config::Initialize();
    Config::Load(Config::ConfigOptions{});
    Libs::LibNet::InitNet_1_Net(&symbols);
    ntoa = Function<StartNtoa>("Nd91WaWmG2w");
    multiple = Function<StartNtoaMultipleRecords>("RCCY01Xd+58");
    ASSERT_NE(ntoa, nullptr);
    ASSERT_NE(multiple, nullptr);
    Network::Initialize();
    pool_id = Network::Net::NetPoolCreate("net", 0x10000, 0);
    rid = Network::Net::NetResolverCreate("resolver", pool_id, 0);
    ASSERT_GE(rid, 0);
  }

  void TearDown() override {
    Network::Shutdown();
    Config::Shutdown();
  }

  template <typename T> T Function(const char *nid) const {
    const auto *record = symbols.FindByNid(nid, Loader::SymbolType::Func);
    return record != nullptr ? reinterpret_cast<T>(record->vaddr) : nullptr;
  }

  Loader::SymbolDatabase symbols;
  StartNtoa ntoa = nullptr;
  StartNtoaMultipleRecords multiple = nullptr;
  int pool_id = -1;
  int rid = -1;
};

TEST_F(NetResolverTest, UnnamedResolverIsAllowed) {
  const int unnamed_rid = Network::Net::NetResolverCreate(nullptr, pool_id, 0);
  ASSERT_GE(unnamed_rid, 0);
  EXPECT_EQ(Network::Net::NetResolverDestroy(unnamed_rid), 0);
}

TEST_F(NetResolverTest, MultipleRecordsStoresAddressLiteral) {
  NetResolverInfo info;
  std::memset(&info, 0xff, sizeof(info));
  ASSERT_EQ(multiple(rid, "10.1.2.3", &info, 0, 0, 0), 0);

  NetResolverInfo expected{};
  expected.addrs[0].addr = 0x0302010au;
  expected.addrs[0].af = 2;
  expected.records = 1;
  expected.dns4records = 1;
  EXPECT_EQ(std::memcmp(&info, &expected, sizeof(info)), 0);
}

TEST_F(NetResolverTest, MultipleRecordsReturnsEnodnsWhenOffline) {
  NetResolverInfo info{};
  EXPECT_EQ(multiple(rid, "localhost", &info, 0, 0, 0),
            Network::NET_ERROR_RESOLVER_ENODNS);
}

TEST_F(NetResolverTest, MultipleRecordsRejectsBadArguments) {
  NetResolverInfo info{};
  EXPECT_EQ(multiple(rid, "10.1.2.3", nullptr, 0, 0, 0),
            Network::NET_ERROR_EINVAL);
  EXPECT_EQ(multiple(rid, nullptr, &info, 0, 0, 0), Network::NET_ERROR_EINVAL);
  EXPECT_EQ(multiple(rid + 1, "10.1.2.3", &info, 0, 0, 0),
            Network::NET_ERROR_EBADF);
}

TEST_F(NetResolverTest, NtoaStoresAddressLiteralAndFailsHostnameOffline) {
  uint32_t addr = 0;
  ASSERT_EQ(ntoa(rid, "10.1.2.3", &addr, 0, 0, 0), 0);
  EXPECT_EQ(addr, 0x0302010au);
  EXPECT_EQ(ntoa(rid, "localhost", &addr, 0, 0, 0),
            Network::NET_ERROR_RESOLVER_ENODNS);
}

TEST_F(NetResolverTest, SocketReuseAddressOption) {
  const int s = Network::Net::Socket(2, 1, 6);
  ASSERT_GE(s, 0);
  const int enable = 1;
  EXPECT_EQ(Network::Net::Setsockopt(s, 0xffff, 0x4, &enable, sizeof(enable)),
            0);
  int value = 0;
  uint32_t length = sizeof(value);
  EXPECT_EQ(Network::Net::Getsockopt(s, 0xffff, 0x4, &value, &length), 0);
  EXPECT_NE(value, 0);
  EXPECT_EQ(Network::Net::SocketClose(s), 0);
}

TEST_F(NetResolverTest, Gt7NetworkAndVrTrackerNidsResolve) {
  Loader::SymbolDatabase all_symbols;
  Libs::InitNet_1(&all_symbols);
  Libs::InitVrTracker2_1(&all_symbols);
  for (const char *nid : {"UVCMLmS-Eas", "KWkc6Q3tjXc", "lxtHJMwBsaU",
                          "PM3IZCw-7m0", "aBuX0PX-T7I", "r8mVMwlafF8"}) {
    const auto *record = all_symbols.FindByNid(nid, Loader::SymbolType::Func);
    ASSERT_NE(record, nullptr) << "Missing NID: " << nid;
    EXPECT_NE(record->vaddr, 0u) << "Null address for NID: " << nid;
  }
}

} // namespace

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
