#include <cstdio>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#define NOMINMAX
#include <windows.h>
#include <shlwapi.h>
#include <delayimp.h>
#include <crtdbg.h>
#include "wgetopt.h"
#include "strutil.h"
#include "util.h"
#include "win32util.h"
#include "CAFDecoder.h"

class StreamReaderImpl: public IStreamReader {
    std::shared_ptr<FILE> m_fp;
public:
    StreamReaderImpl(const std::wstring &filename)
    {
        m_fp = win32::fopen(filename, L"rb");
    }
    int fd() const
    {
        return _fileno(m_fp.get());
    }
    ssize_t read(void *data, size_t size)
    {
        return _read(fd(), data, size);
    }
    int seek(int64_t off, int whence)
    {
        int64_t newoff = _lseeki64(fd(), off, whence);
        return newoff < 0 ? -1 : 0;
    }
    int64_t get_position()
    {
        return _lseeki64(fd(), 0, SEEK_CUR);
    }
    int64_t get_size()
    {
        return _filelengthi64(fd());
    }
};

namespace wave {
    struct GUID {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t  Data4[8];
    };
    GUID ksFormatSubTypePCM = {
        0x1, 0x0, 0x10, { 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 }
    };
    GUID ksFormatSubTypeFloat = {
        0x3, 0x0, 0x10, { 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 }
    };
}

class WaveMuxer {
    bool m_seekable;
    uint32_t m_chanmask;
    uint32_t m_data_pos;
    uint64_t m_duration;
    uint64_t m_bytes_written;
    std::shared_ptr<FILE> m_ofp;
    std::vector<uint32_t> m_chanmap;
    AudioStreamBasicDescription m_asbd;
public:
    WaveMuxer(std::shared_ptr<FILE> &ofp,
              const AudioStreamBasicDescription &asbd,
              uint32_t chanmask)
        : m_chanmask(chanmask),
          m_data_pos(0),
          m_bytes_written(0),
          m_ofp(ofp),
          m_asbd(asbd)
    {
        m_seekable = util::is_seekable(_fileno(m_ofp.get()));

        std::string header = buildHeader();

        uint32_t hdrsize = header.size();
        write("RIFF\377\377\377\377WAVE", 12);
        if (m_seekable) {
            write("JUNK", 4);
            static const char filler[32] = { 0x1c, 0 };
            write(filler, 32);
        }
        write("fmt ", 4);
        write(&hdrsize, 4);
        write(header.c_str(), hdrsize);
        write("data\377\377\377\377", 8);
        m_data_pos = 28 + hdrsize + (m_seekable ? 36 : 0);
    }
    ~WaveMuxer()
    {
        finishWrite();
    }
    void writeSamples(const void *data, size_t nsamples)
    {
        size_t nbytes = nsamples * m_asbd.mBytesPerFrame;
        write(data, nbytes);
        m_bytes_written += nbytes;
    }
private:
    template <typename T>
    void put(std::streambuf *os, T obj)
    {
        os->sputn(reinterpret_cast<char*>(&obj), sizeof obj);
    }
    void write(const void *data, size_t len)
    {
        _fwrite_nolock(data, 1, len, m_ofp.get());
        if (ferror(m_ofp.get()))
            util::throw_crt_error("fwrite()");
    }
    std::string buildHeader()
    {
        std::stringstream ss;
        std::streambuf *sb = ss.rdbuf();
        uint16_t format = 1; // WAVE_FORMAT_PCM
        if ((m_chanmask && m_asbd.mChannelsPerFrame > 2) ||
            m_asbd.mBitsPerChannel > 16 ||
            (m_asbd.mBitsPerChannel & 0x7) != 0)
            format = 0xfffe; // WAVE_FORMAT_EXTENSIBLE
        put(sb, format);
        put(sb, static_cast<int16_t>(m_asbd.mChannelsPerFrame));
        put(sb, static_cast<int32_t>(m_asbd.mSampleRate));
        int32_t bytes_per_sec = m_asbd.mSampleRate * m_asbd.mBytesPerFrame;
        put(sb, bytes_per_sec);
        put(sb, static_cast<int16_t>(m_asbd.mBytesPerFrame));
        uint16_t bpc = (m_asbd.mBytesPerFrame / m_asbd.mChannelsPerFrame) << 3;
        put(sb, bpc);
        if (format == 0xfffe) {
            put(sb, static_cast<int16_t>(22));
            put(sb, static_cast<int16_t>(m_asbd.mBitsPerChannel));
            put(sb, m_chanmask);
            if (m_asbd.mFormatFlags & kAudioFormatFlagIsFloat)
                put(sb, wave::ksFormatSubTypeFloat);
            else
                put(sb, wave::ksFormatSubTypePCM);
        }
        return ss.str();
    }
    void finishWrite()
    {
        if (m_bytes_written & 1)
            write("\0", 1);
        if (!m_seekable)
            return;
        uint64_t datasize64 = m_bytes_written;
        uint64_t riffsize64 = m_data_pos + datasize64 - 8;
        if (riffsize64 >> 32 == 0) {
            if (!std::fseek(m_ofp.get(), m_data_pos - 4, SEEK_SET)) {
                uint32_t size32 = static_cast<uint32_t>(datasize64);
                write(&size32, 4);
                if (!std::fseek(m_ofp.get(), 4, SEEK_SET)) {
                    uint32_t size32 = static_cast<uint32_t>(riffsize64);
                    write(&size32, 4);
                }
            }
        } else {
            std::rewind(m_ofp.get());
            write("RF64", 4);
            std::fseek(m_ofp.get(), 8, SEEK_CUR);
            write("ds64", 4);
            std::fseek(m_ofp.get(), 4, SEEK_CUR);
            write(&riffsize64, 8);
            write(&datasize64, 8);
            uint64_t nsamples = m_bytes_written / m_asbd.mBytesPerFrame;
            write(&nsamples, 8);
        }
    }
};

static
void process(const std::wstring &ifilename, std::shared_ptr<FILE> &ofp,
             int64_t skip, int64_t duration)
{
    std::shared_ptr<IStreamReader>
        reader(new StreamReaderImpl(ifilename));
    CAFDecoder decoder(reader);
    WaveMuxer muxer(ofp, decoder.getOutputFormat(),
                    decoder.getChannelMask());
    int percent = 0;
    try {
        int64_t total = decoder.getLength();
        decoder.seek(std::min(total, skip));
        total = std::max(total - skip, 0LL);
        total = std::min(total, duration);

        int64_t samples_read = 0;
        uint32_t bpf = decoder.getOutputFormat().mBytesPerFrame;
        std::vector<uint8_t> buffer(4096 * bpf);
        size_t nsamples;
        while ((nsamples = decoder.readSamples(&buffer[0], 4096)) > 0) {
            if (samples_read + nsamples > total)
                nsamples = total - samples_read;
            muxer.writeSamples(&buffer[0], nsamples);
            samples_read += nsamples;
            int p = 100.0 * samples_read / total + 0.5;
            if (p != percent) {
                std::fwprintf(stderr, L"\r%d%% processed", p);
                percent = p;
            }
        }
    } catch (...) {
        std::putwc('\n', stderr);
        throw;
    }
    std::putwc('\n', stderr);
}

static
std::wstring getAppleApplicationSupportPath()
{
    HKEY hKey = 0;
    const wchar_t *subkey =
        L"SOFTWARE\\Apple Inc.\\Apple Application Support";
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
                               KEY_READ, &hKey);
    if (rc == ERROR_SUCCESS) {
        std::shared_ptr<HKEY__> hKeyPtr(hKey, RegCloseKey);
        DWORD size;
        rc = RegQueryValueExW(hKey, L"InstallDir", 0, 0, 0, &size);
        if (rc == ERROR_SUCCESS) {
            std::vector<wchar_t> vec(size/sizeof(wchar_t));
            rc = RegQueryValueExW(hKey, L"InstallDir", 0, 0,
                                  reinterpret_cast<LPBYTE>(&vec[0]), &size);
            if (rc == ERROR_SUCCESS)
                return &vec[0];
        }
    }
    return L"";
}

static
std::string getCoreAudioToolboxVersion(HMODULE hDll)
{
    HRSRC hRes = FindResourceExW(hDll,
                                 RT_VERSION,
                                 MAKEINTRESOURCEW(VS_VERSION_INFO),
                                 MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
    std::string data;
    {
        DWORD cbres = SizeofResource(hDll, hRes);
        HGLOBAL hMem = LoadResource(hDll, hRes);
        if (hMem) {
            char *pc = static_cast<char*>(LockResource(hMem));
            if (pc && cbres)
                data.assign(pc, cbres);
            FreeResource(hMem);
        }
    }
    // find dwSignature of VS_FIXEDFILEINFO
    std::stringstream ss;
    size_t pos = data.find("\xbd\x04\xef\xfe");
    if (pos != std::string::npos) {
        VS_FIXEDFILEINFO vfi;
        std::memcpy(&vfi, data.c_str() + pos, sizeof vfi);
        WORD v[4];
        v[0] = HIWORD(vfi.dwFileVersionMS);
        v[1] = LOWORD(vfi.dwFileVersionMS);
        v[2] = HIWORD(vfi.dwFileVersionLS);
        v[3] = LOWORD(vfi.dwFileVersionLS);
        ss << v[0] << "." << v[1] << "." << v[2] << "." << v[3];
    }
    return ss.str();
}

static
HMODULE load_coreaudio_toolbox()
{
    std::wstring path = win32::get_module_directory();
    std::vector<std::wstring> candidates;
    candidates.push_back(path);
    candidates.push_back(path + L"QTfiles\\");
    if ((path = getAppleApplicationSupportPath()) != L"") {
        if (path.back() != L'\\')
            path.push_back(L'\\');
        candidates.push_back(path);
    }
    std::vector<std::wstring>::const_iterator it;
    HMODULE hmod = 0;
    for (it = candidates.begin(); it != candidates.end(); ++it) {
        path = *it + L"CoreAudioToolbox.dll";
        hmod = LoadLibraryExW(path.c_str(), 0,
                              LOAD_WITH_ALTERED_SEARCH_PATH);
        if (hmod)
            break;
    }
    if (!hmod) {
        throw std::runtime_error("Cannot load CoreAudioToolbox.dll");
    }
    return hmod;
}

static
FARPROC WINAPI dll_failure_hook(unsigned notify, PDelayLoadInfo pdli)
{
    win32::throw_error(pdli->szDll, pdli->dwLastError);
    return 0;
}

void usage()
{
    std::fputws(
L"Usage: cafdec [-s number] [-n number] INFILE [OUTFILE]\n"
L"\n"
L"Options:\n"
L"-s number          skip samples at beginning\n"
L"-n number          set decode duration with number of samples\n"
    , stderr);
    std::exit(1);
}

int wmain(int argc, wchar_t **argv)
{
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_CHECK_ALWAYS_DF);
#endif
    _setmode(0, _O_BINARY);
    _setmode(2, _O_U8TEXT);
    std::setbuf(stderr, 0);

    int64_t skip = 0;
    int64_t duration = std::numeric_limits<int64_t>::max();
    int ch;
    while ((ch = getopt::getopt(argc, argv, L"s:n:")) != -1) {
        switch (ch) {
        case 's':
            if (std::swscanf(getopt::optarg, L"%lld", &skip) != 1)
                usage();
            break;
        case 'n':
            if (std::swscanf(getopt::optarg, L"%lld", &duration) != 1)
                usage();
            break;
        default:
            usage();
        }
    }
    argc -= getopt::optind;
    argv += getopt::optind;
    if (argc < 1)
        usage();
    try {
        __pfnDliFailureHook2 = dll_failure_hook;
        std::shared_ptr<HINSTANCE__> C(load_coreaudio_toolbox(), FreeLibrary);
        std::string ver = getCoreAudioToolboxVersion(C.get());
        std::fwprintf(stderr, L"CoreAudioToolbox %hs\n", ver.c_str());

        std::wstring ofilename;
        if (argc > 1)
            ofilename = argv[1];
        else {
            std::wstring basename = PathFindFileNameW(argv[0]);
            ofilename = win32::PathReplaceExtension(basename, L".wav");
        }
        if (ofilename == L"-")
            _setmode(1, _O_BINARY);
        std::shared_ptr<FILE> ofp = win32::fopen(ofilename, L"wb");
        process(argv[0], ofp, skip, duration);
        return 0;
    } catch (const std::exception & e) {
        std::fwprintf(stderr, L"ERROR: %s\n", strutil::us2w(e.what()).c_str());
        return 2;
    }
}
