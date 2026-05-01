/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TRANSIENTS_H
#define SQUID_SRC_TRANSIENTS_H

#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "Store.h"
#include "store/Controlled.h"
#include "store/forward.h"
#include <vector>

typedef Ipc::StoreMap TransientsMap;

/// A Transients entry allows workers to Broadcast() DELETE requests and swapout
/// progress updates. In a collapsed forwarding context, it also represents a CF
/// initiating worker promise to either cache the response or inform the waiting
/// slaves (via false EntryStatus::hasWriter) that caching will not happen. A
/// Transients entry itself does not carry response- or Store-specific metadata.
class Transients: public Store::Controlled, public Ipc::StoreMapCleaner
{
public:
    /// shared entry metadata, used for synchronization
    class EntryStatus
    {
    public:
        bool hasWriter = false; ///< whether some worker is storing the entry
        bool waitingToBeFreed = false; ///< whether the entry was marked for deletion
        bool updateApplied = false; ///< whether the 304 entry has been applied to the revalidated entry
    };

    /// Maps local reader and writer StoreEntries to their transient ID.
    /// There can be many StoreEntries with the same transient ID.
    class Locals {
    public:
        /// keeps StoreEntries with the same transient ID (e.g., a stale StoreEntry
        /// and a refreshed by 304 StoreEntry)
        using Entries = std::list<StoreEntry*>;
        /// maps transient ID index to Entries list
        using Index = std::vector<Entries>;

        explicit Locals(const size_t size) : index(size) {}

        /// \returns most recently added StoreEntry with the given fileno
        StoreEntry *freshest(const sfileno fileno) {
            const auto &entries = index.at(fileno);
            return entries.empty() ? nullptr : entries.back();
        }
        bool exists(const  StoreEntry &entry) const {
            const auto &entries = index.at(entry.mem_obj->xitTable.index);
            return std::find(entries.begin(), entries.end(), &entry) != entries.end();
        }

        void add(StoreEntry &entry) {
            auto &entries = index.at(entry.mem().xitTable.index);
            entries.push_back(&entry);
        }

        void remove(const StoreEntry &entry) {
            auto &entries = index.at(entry.mem().xitTable.index);
            auto it = std::find(entries.begin(), entries.end(), &entry);
            Assure(it != entries.end());
            entries.erase(it);
        }

        Index index;
    };

    Transients();
    ~Transients() override;

    /// return a local, previously collapsed entry
    Transients::Locals::Entries *findCollapsed(const sfileno xitIndex);

    /// start listening for remote DELETE requests targeting either a complete
    /// StoreEntry (ioReading) or a being-formed miss StoreEntry (ioWriting)
    void monitorIo(StoreEntry*, const cache_key*, const Store::IoStatus);

    /// called when the in-transit entry has been successfully cached
    void completeWriting(const StoreEntry &e);

    /// copies current shared entry metadata into entryStatus
    void status(const StoreEntry &e, EntryStatus &entryStatus) const;

    /// \copydoc Store::Controller::appliedForUpdate()
    /// \prec the entry is opened for writing
    void appliedForUpdate(StoreEntry &e, const StoreEntry &);

    /// number of entry readers some time ago
    int readers(const StoreEntry &e) const;

    /// the caller is done writing or reading the given entry
    void disconnect(StoreEntry &);

    /* Store API */
    StoreEntry *get(const cache_key *) override;
    void create() override {}
    void init() override;
    uint64_t maxSize() const override;
    uint64_t minSize() const override;
    uint64_t currentSize() const override;
    uint64_t currentCount() const override;
    int64_t maxObjectSize() const override;
    void getStats(StoreInfoStats &stats) const override;
    void stat(StoreEntry &e) const override;
    void reference(StoreEntry &e) override;
    bool dereference(StoreEntry &e) override;
    void evictCached(StoreEntry &) override;
    void evictIfFound(const cache_key *) override;
    void maintain() override;

    /// Whether an entry with the given public key exists and (but) was
    /// marked for removal some time ago; get(key) returns nil in such cases.
    bool markedForDeletion(const cache_key *) const;

    /// whether the entry is in "reading from Transients" I/O state
    bool isReader(const StoreEntry &) const;
    /// whether the entry is in "writing to Transients" I/O state
    bool isWriter(const StoreEntry &) const;
    /// whether we or somebody else is in the "writing to Transients" I/O state
    bool hasWriter(const StoreEntry &);
    /// whether for the given key there is a shared entry that is fresher than
    /// the local entry
    bool localIsStale(const cache_key *key) const;

    static int64_t EntryLimit();

    /// Can we create and initialize Transients?
    static bool Enabled() { return EntryLimit(); }

private:
    void addEntry(StoreEntry*, const cache_key *, const Store::IoStatus);
    void addWriterEntry(StoreEntry &, const cache_key *);
    void addReaderEntry(StoreEntry &, const cache_key *);

    // Ipc::StoreMapCleaner API
    void noteFreeMapSlice(const Ipc::StoreMapSliceId sliceId) override;

private:
    /// shared packed info indexed by Store keys, for creating new StoreEntries
    TransientsMap *map;

    /// local collapsed reader and writer entries, indexed by transient ID,
    /// for syncing old StoreEntries
    Locals *locals;
};

// TODO: Why use Store as a base? We are not really a cache.

#endif /* SQUID_SRC_TRANSIENTS_H */

