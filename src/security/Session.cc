/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    TLS session management */

#include "squid.h"
#include "anyp/PortCfg.h"
#include "base/RunnersRegistry.h"
#include "CachePeer.h"
#include "debug/Stream.h"
#include "fd.h"
#include "fde.h"
#include "ipc/MemMap.h"
#include "security/Session.h"
#include "SquidConfig.h"
#include "ssl/bio.h"

#define SSL_SESSION_ID_SIZE 32
#define SSL_SESSION_MAX_SIZE 10*1024

#if USE_OPENSSL
static Ipc::MemMap *SessionCache = nullptr;
static const char *SessionCacheName = "tls_session_cache";
#endif

#if USE_OPENSSL || USE_GNUTLS
static int
tls_read_method(int fd, char *buf, int len)
{
    auto session = fd_table[fd].ssl.get();
    debugs(83, 3, "started for session=" << (void*)session);

#if USE_OPENSSL
    int i = SSL_read(session, buf, len);
#elif USE_GNUTLS
    int i = gnutls_record_recv(session, buf, len);
#endif

    if (i > 0) {
        debugs(83, 8, "TLS FD " << fd << " session=" << (void*)session << " " << i << " bytes");
        (void)VALGRIND_MAKE_MEM_DEFINED(buf, i);
    }

#if USE_OPENSSL
    if (i > 0 && SSL_pending(session) > 0) {
#elif USE_GNUTLS
    if (i > 0 && gnutls_record_check_pending(session) > 0) {
#endif
        debugs(83, 2, "TLS FD " << fd << " is pending");
        fd_table[fd].flags.read_pending = true;
    } else
        fd_table[fd].flags.read_pending = false;

    return i;
}

static int
tls_write_method(int fd, const char *buf, int len)
{
    auto session = fd_table[fd].ssl.get();
    debugs(83, 3, "started for session=" << (void*)session);

#if USE_OPENSSL
    if (!SSL_is_init_finished(session)) {
        errno = ENOTCONN;
        return -1;
    }
#endif

#if USE_OPENSSL
    int i = SSL_write(session, buf, len);
#elif USE_GNUTLS
    int i = gnutls_record_send(session, buf, len);
#endif

    if (i > 0) {
        debugs(83, 8, "TLS FD " << fd << " session=" << (void*)session << " " << i << " bytes");
    }
    return i;
}
#endif

#if USE_OPENSSL
Security::SessionPointer
Security::NewSessionObject(const Security::ContextPointer &ctx)
{
    Security::SessionPointer session(SSL_new(ctx.get()), [](SSL *p) {
        debugs(83, 5, "SSL_free session=" << (void*)p);
        SSL_free(p);
    });
    debugs(83, 5, "SSL_new session=" << (void*)session.get());
    return session;
}
#endif

static bool
CreateSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &conn, Security::PeerOptions &opts, Security::Io::Type type, const char *squidCtx)
{
    if (!Comm::IsConnOpen(conn)) {
        debugs(83, DBG_IMPORTANT, "Gone connection");
        return false;
    }

#if USE_OPENSSL || USE_GNUTLS

    const char *errAction = "with no TLS/SSL library";
    Security::LibErrorCode errCode = 0;
#if USE_OPENSSL
    Security::SessionPointer session(Security::NewSessionObject(ctx));
    if (!session) {
        errCode = ERR_get_error();
        errAction = "failed to allocate handle";
        debugs(83, DBG_IMPORTANT, "ERROR: TLS failure: " << errAction << ": " << Security::ErrorString(errCode));
    }
#elif USE_GNUTLS
    gnutls_session_t tmp;
    errCode = gnutls_init(&tmp, static_cast<unsigned int>(type) | GNUTLS_NONBLOCK);
    Security::SessionPointer session(tmp, [](gnutls_session_t p) {
        debugs(83, 5, "gnutls_deinit session=" << (void*)p);
        gnutls_deinit(p);
    });
    debugs(83, 5, "gnutls_init " << (type == Security::Io::BIO_TO_SERVER ? "client" : "server" )<< " session=" << (void*)session.get());
    if (errCode != GNUTLS_E_SUCCESS) {
        session.reset();
        errAction = "failed to initialize session";
        debugs(83, DBG_IMPORTANT, "ERROR: TLS failure: " << errAction << ": " << Security::ErrorString(errCode));
    }
#endif /* USE_GNUTLS */

    if (session) {
        const int fd = conn->fd;

#if USE_OPENSSL
        // without BIO, we would call SSL_set_fd(ssl.get(), fd) instead
        if (BIO *bio = Ssl::Bio::Create(fd, type)) {
            Ssl::Bio::Link(session.get(), bio); // cannot fail
#elif USE_GNUTLS
        errCode = gnutls_credentials_set(session.get(), GNUTLS_CRD_CERTIFICATE, ctx.get());
        if (errCode == GNUTLS_E_SUCCESS) {

            opts.updateSessionOptions(session);

            // NP: GnuTLS does not yet support the BIO operations
            //     this does the equivalent of SSL_set_fd() for now.
            gnutls_transport_set_int(session.get(), fd);
            gnutls_handshake_set_timeout(session.get(), GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#endif /* USE_GNUTLS */

            debugs(83, 5, "link FD " << fd << " to TLS session=" << (void*)session.get());

            fd_table[fd].ssl = session;
            fd_table[fd].useBufferedIo(&tls_read_method, &tls_write_method);
            fd_note(fd, squidCtx);
            return true;
        }

#if USE_OPENSSL
        errCode = ERR_get_error();
        errAction = "failed to initialize I/O";
        (void)opts;
#elif USE_GNUTLS
        errAction = "failed to assign credentials";
#endif
    }

    debugs(83, DBG_IMPORTANT, "ERROR: " << squidCtx << ' ' << errAction <<
           ": " << (errCode != 0 ? Security::ErrorString(errCode) : ""));
#else
    (void)ctx;
    (void)opts;
    (void)type;
    (void)squidCtx;
#endif /* USE_OPENSSL || USE_GNUTLS */
    return false;
}

bool
Security::CreateClientSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &c, const char *squidCtx)
{
    if (!c || !c->getPeer())
        return CreateSession(ctx, c, Security::ProxyOutgoingConfig, Security::Io::BIO_TO_SERVER, squidCtx);

    auto *peer = c->getPeer();
    return CreateSession(ctx, c, peer->secure, Security::Io::BIO_TO_SERVER, squidCtx);
}

bool
Security::CreateServerSession(const Security::ContextPointer &ctx, const Comm::ConnectionPointer &c, Security::PeerOptions &o, const char *squidCtx)
{
    return CreateSession(ctx, c, o, Security::Io::BIO_TO_CLIENT, squidCtx);
}

void
Security::SessionSendGoodbye(const Security::SessionPointer &s)
{
    debugs(83, 5, "session=" << (void*)s.get());
    if (s) {
#if USE_OPENSSL
        SSL_shutdown(s.get());
#elif USE_GNUTLS
        gnutls_bye(s.get(), GNUTLS_SHUT_RDWR);
#endif
    }
}

bool
Security::SessionIsResumed(const Security::SessionPointer &s)
{
    bool result = false;
#if USE_OPENSSL
    result = SSL_session_reused(s.get()) == 1;
#elif USE_GNUTLS
    result = gnutls_session_is_resumed(s.get()) != 0;
#endif
    debugs(83, 7, "session=" << (void*)s.get() << ", query? answer: " << (result ? 'T' : 'F') );
    return result;
}

void
Security::MaybeGetSessionResumeData(const Security::SessionPointer &s, Security::SessionStatePointer &data)
{
    if (!SessionIsResumed(s)) {
#if USE_OPENSSL
        // nil is valid for SSL_get1_session(), it cannot fail.
        data.reset(SSL_get1_session(s.get()));
#elif USE_GNUTLS
        gnutls_datum_t *tmp = nullptr;
        const auto x = gnutls_session_get_data2(s.get(), tmp);
        if (x != GNUTLS_E_SUCCESS) {
            debugs(83, 3, "session=" << (void*)s.get() << " error: " << Security::ErrorString(x));
        }
        data.reset(tmp);
#endif
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get());
    } else {
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get() << ", do nothing.");
    }
}

void
Security::SetSessionResumeData(const Security::SessionPointer &s, const Security::SessionStatePointer &data)
{
    if (data) {
#if USE_OPENSSL
        if (!SSL_set_session(s.get(), data.get())) {
            const auto ssl_error = ERR_get_error();
            debugs(83, 3, "session=" << (void*)s.get() << " data=" << (void*)data.get() <<
                   " resume error: " << Security::ErrorString(ssl_error));
        }
#elif USE_GNUTLS
        const auto x = gnutls_session_set_data(s.get(), data->data, data->size);
        if (x != GNUTLS_E_SUCCESS) {
            debugs(83, 3, "session=" << (void*)s.get() << " data=" << (void*)data.get() <<
                   " resume error: " << Security::ErrorString(x));
        }
#else
        // critical because, how did it get here?
        debugs(83, DBG_CRITICAL, "no TLS library. session=" << (void*)s.get() << " data=" << (void*)data.get());
#endif
        debugs(83, 5, "session=" << (void*)s.get() << " data=" << (void*)data.get());
    } else {
        debugs(83, 5, "session=" << (void*)s.get() << " no resume data");
    }
}

static bool
isTlsServer()
{
    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (s->secure.encryptTransport)
            return true;
        if (s->flags.tunnelSslBumping)
            return true;
    }

    return false;
}

#if USE_OPENSSL
static int
store_session_cb(SSL *, SSL_SESSION *session)
{
    if (!SessionCache)
        return 0;

    debugs(83, 5, "Request to store SSL_SESSION");

    SSL_SESSION_set_timeout(session, Config.SSL.session_ttl);

    unsigned int idlen;
    const unsigned char *id = SSL_SESSION_get_id(session, &idlen);
    // XXX: the other calls [to openForReading()] do not copy the sessionId to a char buffer, does this really have to?
    unsigned char key[MEMMAP_SLOT_KEY_SIZE];
    // Session ids are of size 32bytes. They should always fit to a
    // MemMap::Slot::key
    assert(idlen <= MEMMAP_SLOT_KEY_SIZE);
    memset(key, 0, sizeof(key));
    memcpy(key, id, idlen);
    int pos;
    if (auto slotW = SessionCache->openForWriting(static_cast<const cache_key*>(key), pos)) {
        int lenRequired = i2d_SSL_SESSION(session, nullptr);
        if (lenRequired <  MEMMAP_SLOT_DATA_SIZE) {
            unsigned char *p = static_cast<unsigned char *>(slotW->p);
            lenRequired = i2d_SSL_SESSION(session, &p);
            slotW->set(key, nullptr, lenRequired, squid_curtime + Config.SSL.session_ttl);
        }
        SessionCache->closeForWriting(pos);
        debugs(83, 5, "wrote an SSL_SESSION entry of size " << lenRequired << " at pos " << pos);
    }
    return 0;
}

static void
remove_session_cb(SSL_CTX *, SSL_SESSION *sessionID)
{
    if (!SessionCache)
        return;

    debugs(83, 5, "Request to remove corrupted or not valid SSL_SESSION");
    int pos;
    if (SessionCache->openForReading(reinterpret_cast<const cache_key*>(sessionID), pos)) {
        SessionCache->closeForReading(pos);
        // TODO:
        // What if we are not able to remove the session?
        // Maybe schedule a job to remove it later?
        // For now we just have an invalid entry in cache until will be expired
        // The OpenSSL library will reject it when we try to use it
        SessionCache->free(pos);
    }
}

static SSL_SESSION *
#if SQUID_USE_CONST_SSL_SESSION_CBID
get_session_cb(SSL *, const unsigned char *sessionID, int len, int *copy)
#else
get_session_cb(SSL *, unsigned char *sessionID, int len, int *copy)
#endif
{
    if (!SessionCache)
        return nullptr;

    const unsigned int *p = reinterpret_cast<const unsigned int *>(sessionID);
    debugs(83, 5, "Request to search for SSL_SESSION of len: " <<
           len << p[0] << ":" << p[1]);

    SSL_SESSION *session = nullptr;
    int pos;
    if (const auto slot = SessionCache->openForReading(static_cast<const cache_key*>(sessionID), pos)) {
        if (slot->expire > squid_curtime) {
            const unsigned char *ptr = slot->p;
            session = d2i_SSL_SESSION(nullptr, &ptr, slot->pSize);
            debugs(83, 5, "SSL_SESSION retrieved from cache at pos " << pos);
        } else
            debugs(83, 5, "SSL_SESSION in cache expired");
        SessionCache->closeForReading(pos);
    }

    if (!session)
        debugs(83, 5, "Failed to retrieve SSL_SESSION from cache");

    // With the parameter copy the callback can require the SSL engine
    // to increment the reference count of the SSL_SESSION object, Normally
    // the reference count is not incremented and therefore the session must
    // not be explicitly freed with SSL_SESSION_free(3).
    *copy = 0;
    return session;
}

#define KEY_RENEW_TIME 3*60*60
#define KEY_STORE_ITEMS 3
#define KEY_LIFE_TIME (KEY_STORE_ITEMS - 1) * KEY_RENEW_TIME
class Rfc5077KeyStore {
public:
    struct TicketKey {
        unsigned char name[16];
        unsigned char aes_key[16];
        unsigned char hmac_key[16];
        time_t expire;
        void renew() {
            RAND_bytes(name, 16);
            RAND_bytes(aes_key, 16);
            RAND_bytes(hmac_key, 16);
            //TODO: implement a way to build random octets.
            expire = squid_curtime + KEY_LIFE_TIME;

        }
        bool expired() {
            return expire < squid_curtime;
        }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        void getMacParams(OSSL_PARAM &params[3]) {
            params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, hmac_key, 16);
            params[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "sha256", 0);
            params[2] = OSSL_PARAM_construct_end();
        }
#endif
    };

    class Store {
    public:
        Store(const int aLimit, const size_t anExtrasSize) {}
        Store() {}

        size_t sharedMemorySize() const {return SharedMemorySize(0, 0);}
        static size_t SharedMemorySize(const int limit, const size_t extrasSize);
        std::atomic<int64_t> count;
        TicketKey keys[KEY_STORE_ITEMS];
    };
    typedef Ipc::Mem::Owner<Store> Owner;

    class Manager {
    public:
        Manager(const Rfc5077KeyStore &keystore);
        ~Manager();
        void renew();
        static void RenewEvent(void *);
    public:
        Ipc::Mem::Pointer<Store> store;
    };

    class Reader {
    public:
        Reader(const Rfc5077KeyStore &keystore);
        bool isLatest(TicketKey &key);
        TicketKey *currentKey();
        TicketKey *findKey(unsigned char keyName[16]);
    public:
        Ipc::Mem::Pointer<Store> store;
    };

    Rfc5077KeyStore(const char *aName): name(aName), store(shm_old(Store)(aName)), reader(nullptr), manager(nullptr) {}
    ~Rfc5077KeyStore(){
        delete reader;
        delete manager;
    }

public:

    void initReader();
    void initManager();
    static Owner *Create(const char *aName);

    std::string name;
    Ipc::Mem::Pointer<Store> store;
    Reader *reader;
    Manager *manager;
};

void Rfc5077KeyStore::initReader()
{
    reader = new Reader(*this);
}

void Rfc5077KeyStore::initManager()
{
    manager = new Manager(*this);
}

Rfc5077KeyStore::Owner *Rfc5077KeyStore::Create(const char *aName)
{
    debugs(84, 3, "Build Key store\n");
    auto owner = shm_new(Store)(aName, sizeof(Store), 0);
    auto store = owner->object();
    store->count.store(0);
    for(int i = 0; i < KEY_STORE_ITEMS; i++)
        store->keys[i].renew();
    return owner;
}

size_t Rfc5077KeyStore::Store::SharedMemorySize(const int limit, const size_t extrasSize)
{
    return sizeof(Store);
}

Rfc5077KeyStore::Manager::Manager(const Rfc5077KeyStore &keystore): store(keystore.store)
{
    eventAdd("Rfc5077KeyStore::Renew", Rfc5077KeyStore::Manager::RenewEvent,  this, KEY_RENEW_TIME, 1, false);
}

Rfc5077KeyStore::Manager::~Manager() {
    // The following probably will result to a crash if scheduler
    // destructed before this object while squid shutdowns:
    // eventDelete(Rfc5077KeyStore::Manager::RenewEvent,  this);
}

void Rfc5077KeyStore::Manager::renew()
{
    assert(store);
    uint64_t indx = (store->count.load() + 1) % KEY_STORE_ITEMS;
    store->keys[indx].renew();
    store->count++;
    debugs(83, 4, "New key generated in key store");
    eventAdd("Rfc5077KeyStore::Renew", Rfc5077KeyStore::Manager::RenewEvent,  this, KEY_RENEW_TIME, 1, false);
}

void Rfc5077KeyStore::Manager::RenewEvent(void *data)
{
    if (!data)
        return;
    Rfc5077KeyStore::Manager *storeManager = static_cast<Rfc5077KeyStore::Manager *>(data);
    storeManager->renew();
}

Rfc5077KeyStore::Reader::Reader(const Rfc5077KeyStore &keystore): store(keystore.store)
{
}

bool Rfc5077KeyStore::Reader::isLatest(TicketKey &key) {
    uint64_t indx = store->count.load() % KEY_STORE_ITEMS;
    return (memcmp(store->keys[indx].name, key.name, sizeof(TicketKey::name)) == 0);
}

Rfc5077KeyStore::TicketKey *Rfc5077KeyStore::Reader::currentKey() {
    uint64_t indx = store->count.load() % KEY_STORE_ITEMS;
    TicketKey *key = &store->keys[indx];
    return key->expired() ? nullptr : key;
}

Rfc5077KeyStore::TicketKey *Rfc5077KeyStore::Reader::findKey(unsigned char keyName[16])
{
    int64_t currCount = store->count.load();
    int64_t lowerCount = currCount >= KEY_STORE_ITEMS - 1 ? currCount + 2 - KEY_STORE_ITEMS : 0;
    for (int64_t i = currCount; i >= lowerCount; i--) {
        TicketKey *key = &store->keys[i % KEY_STORE_ITEMS];
        if (memcmp(keyName, key->name, sizeof(TicketKey::name)) == 0) {
            debugs(83, 7, "Key found in cache");
            return key->expired() ? nullptr : key;
        }
    }
    debugs(83, 7, "Can not find given key");
    return nullptr;
}

static const char *TicketKeyStoreName = "rfc5077_tickets_store";
std::unique_ptr<Rfc5077KeyStore> TicketKeyStore(nullptr);

static int squid_tlsext_ticket_key_cb(SSL *s, unsigned char key_name[16],
                                      unsigned char *iv,
                                      EVP_CIPHER_CTX *ctx,
#if OPENSSL_VERSION_NUMBER < 0x30000000L
                                      HMAC_CTX *hctx,
#else
                                      EVP_MAC_CTX *mac_ctx,
#endif
                                      int enc)
{
    if (!TicketKeyStore)
        return 0;

    auto ticketStoreReader = TicketKeyStore->reader;
    if (!ticketStoreReader)
        return 0;

    debugs(83, 5, "Squid RFC 5077 shared session tickets, operation: " << enc << "Key name: " << Raw("", (const char *)key_name, 16).hex());
    if (enc) { /* create new session */
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) <= 0)
            return -1; /* insufficient random */

        auto key = ticketStoreReader->currentKey();
        if (!key)
            return 0; //current key not updated?
        memcpy(key_name, key->name, 16);
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key->aes_key, iv);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        HMAC_Init_ex(hctx, key->hmac_key, 16, EVP_sha256(), NULL);
#else
        OSSL_PARAM params[3];
        key->getMacParams(params);
        EVP_MAC_CTX_set_params(mac_ctx, params);
#endif
        return 1;
    } else { /* retrieve session */
        auto key = ticketStoreReader->findKey(key_name);
        if (key == nullptr || key->expired())
            return 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        HMAC_Init_ex(hctx, key->hmac_key, 16, EVP_sha256(), NULL);
#else
        OSSL_PARAM mac_params[3];
        key->getMacParams(mac_params);
        EVP_MAC_CTX_set_params(mac_ctx, mac_params);
#endif
        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key->aes_key, iv);

        if (!ticketStoreReader->isLatest(*key)) {
            // return 2 - This session will get a new ticket even though the
            // current one is still valid.
            return 2;
        }
        return 1;
    }
}

void
Security::SetSessionCacheCallbacks(Security::ContextPointer &ctx)
{
    if (SessionCache) {
        SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL);
        SSL_CTX_sess_set_new_cb(ctx.get(), store_session_cb);
        SSL_CTX_sess_set_remove_cb(ctx.get(), remove_session_cb);
        SSL_CTX_sess_set_get_cb(ctx.get(), get_session_cb);

        // For tlsv1.2 and earlier releases to use RFC5077 tickets
        // which shares sessions across processes we need to setup
        // SSL_CTX_set_tlsext_ticket_key_cb
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        SSL_CTX_set_tlsext_ticket_key_cb(ctx.get(), squid_tlsext_ticket_key_cb);
#else
        SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx.get(), squid_tlsext_ticket_key_cb);
#endif
    }
}
#endif /* USE_OPENSSL */

#if USE_OPENSSL
static void
initializeSessionCache()
{
    // Check if the MemMap keys and data are enough big to hold
    // session ids and session data
    assert(SSL_SESSION_ID_SIZE >= MEMMAP_SLOT_KEY_SIZE);
    assert(SSL_SESSION_MAX_SIZE >= MEMMAP_SLOT_DATA_SIZE);

    TicketKeyStore.reset(new Rfc5077KeyStore(TicketKeyStoreName));
    if (IamPrimaryProcess())
        TicketKeyStore->initManager();
    if (IamWorkerProcess())
        TicketKeyStore->initReader();

    int configuredItems = ::Config.SSL.sessionCacheSize / sizeof(Ipc::MemMap::Slot);
    if (IamWorkerProcess() && configuredItems)
        SessionCache = new Ipc::MemMap(SessionCacheName);
    else {
        SessionCache = nullptr;
        return;
    }

    for (AnyP::PortCfgPointer s = HttpPortList; s != nullptr; s = s->next) {
        if (s->secure.staticContext)
            Security::SetSessionCacheCallbacks(s->secure.staticContext);
    }
}
#endif

/// initializes shared memory segments used by MemStore
class SharedSessionCacheRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    SharedSessionCacheRr(): owner(nullptr), ticketStoreOwner(nullptr) {}
    virtual void useConfig();
    virtual ~SharedSessionCacheRr();

protected:
    virtual void create();

private:
    Ipc::MemMap::Owner *owner;
    Rfc5077KeyStore::Owner *ticketStoreOwner;
};

RunnerRegistrationEntry(SharedSessionCacheRr);

void
SharedSessionCacheRr::useConfig()
{
#if USE_OPENSSL
    if (SessionCache || !isTlsServer()) // no need to configure SSL_SESSION* cache.
        return;

    Ipc::Mem::RegisteredRunner::useConfig();
    initializeSessionCache();
#endif
}

void
SharedSessionCacheRr::create()
{
    if (!isTlsServer()) // no need to configure SSL_SESSION* cache.
        return;

#if USE_OPENSSL
    if (int items = Config.SSL.sessionCacheSize / sizeof(Ipc::MemMap::Slot))
        owner = Ipc::MemMap::Init(SessionCacheName, items);
    ticketStoreOwner = Rfc5077KeyStore::Create(TicketKeyStoreName);
#endif
}

SharedSessionCacheRr::~SharedSessionCacheRr()
{
    // XXX: Enable after testing to reduce at-exit memory "leaks".
    // delete SessionCache;

    delete owner;
    delete ticketStoreOwner;
}

