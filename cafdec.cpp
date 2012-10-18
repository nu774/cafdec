#include <cstdio>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#define NOMINMAX
#include <windows.h>
#include <shlwapi.h>
#include <delayimp.h>
#include <crtdbg.h>
#include "utf8_codecvt_facet.hpp"
#include "strutil.h"
#include "util.h"
#include "ExtAudioFileX.h"
#include "chanmap.h"

namespace callback {
    const int ioErr = -36;

    OSStatus read(void *cookie, SInt64 pos, UInt32 count, void *data,
		  UInt32 *nread)
    {
	FILE *fp = static_cast<FILE*>(cookie);
	if (fseeko(fp, pos, SEEK_SET) == -1)
	    return ioErr;
	*nread = std::fread(data, 1, count, fp);
	return *nread >= 0 ? 0 : ioErr;
    }
    SInt64 size(void *cookie)
    {
	FILE *fp = static_cast<FILE*>(cookie);
	return _filelengthi64(_fileno(fp));
    }
}

class CAFDecoder {
    std::shared_ptr<FILE> m_ifp;
    AudioFileX m_iaf;
    ExtAudioFileX m_eaf;
    int64_t m_length;
    AudioStreamBasicDescription m_iasbd, m_oasbd;
    std::shared_ptr<AudioChannelLayout> m_channel_layout;
public:
    CAFDecoder(const std::wstring &ifilename)
    {
	m_ifp = util::open_file(ifilename, L"rb");
	AudioFileID iafid;
	try {
	    CHECKCA(AudioFileOpenWithCallbacks(m_ifp.get(), callback::read, 0, 
					       callback::size, 0, 0, &iafid));
	} catch (const CoreAudioException &e) {
	    std::stringstream ss;
	    ss << strutil::w2m(ifilename, utf8_codecvt_facet())
	       << ": " << e.what();
	    throw std::runtime_error(ss.str());
	}
	m_iaf.attach(iafid, true);
	if (m_iaf.getFileFormat() != FOURCC('c','a','f','f'))
	    throw std::runtime_error("Not a CAF file");

	std::vector<AudioFormatListItem> aflist;
	m_iaf.getFormatList(&aflist);
	m_iasbd = aflist[0].mASBD;
	if (m_iasbd.mFormatID == FOURCC('a','a','c','p'))
	    throw std::runtime_error("HE-AACv2 is not supported");

	ExtAudioFileRef eaf;
	CHECKCA(ExtAudioFileWrapAudioFileID(m_iaf, false, &eaf));
	m_eaf.attach(eaf, true);

	m_length = m_eaf.getFileLengthFrames();
	m_eaf.getFileChannelLayout(&m_channel_layout);

	bool isMDCT = (m_iasbd.mFormatID == FOURCC('a','a','c',' ') ||
		       m_iasbd.mFormatID == FOURCC('a','a','c','h') ||
		       m_iasbd.mFormatID == FOURCC('a','a','c','p') ||
		       m_iasbd.mFormatID == FOURCC('.','m','p','1') ||
		       m_iasbd.mFormatID == FOURCC('.','m','p','2') ||
		       m_iasbd.mFormatID == FOURCC('.','m','p','3'));
	unsigned bytesPerSample;
	if (m_iasbd.mFormatID == 'alac')
	    bytesPerSample =
		m_iasbd.mFormatFlags == 1 ? 2
					  : m_iasbd.mFormatFlags == 4 ? 4
					 			      : 3;
	else if (isMDCT)
	    bytesPerSample = 4;
	else
	    bytesPerSample = 2;

	m_oasbd = m_iasbd;
	m_oasbd.mFormatID = FOURCC('l','p','c','m');
	m_oasbd.mFormatFlags = kAudioFormatFlagIsPacked;
	if (isMDCT)
	    m_oasbd.mFormatFlags |= kAudioFormatFlagIsFloat;
	else
	    m_oasbd.mFormatFlags |= kAudioFormatFlagIsSignedInteger;
	m_oasbd.mBitsPerChannel = bytesPerSample << 3;
	m_oasbd.mFramesPerPacket = 1;
	m_oasbd.mBytesPerPacket = m_oasbd.mBytesPerFrame =
	    m_oasbd.mChannelsPerFrame * bytesPerSample; 
	m_eaf.setClientDataFormat(m_oasbd);
     }

    int64_t length() const { return m_length; }

    const AudioStreamBasicDescription &getInputFormat() const
    {
	return m_iasbd;
    }
    const AudioStreamBasicDescription &getOutputFormat() const
    {
	return m_oasbd;
    }
    const AudioChannelLayout *getChannelLayout() const
    {
	return m_channel_layout.get();
    }
    uint32_t readSamples(void *buffer, size_t nsamples)
    {
	AudioBufferList abl = { 0 };
	abl.mNumberBuffers = 1;
	abl.mBuffers[0].mData = buffer;
	abl.mBuffers[0].mDataByteSize = nsamples * m_oasbd.mBytesPerPacket;
	UInt32 ns = nsamples;
	CHECKCA(ExtAudioFileRead(m_eaf, &ns, &abl));
	return ns;
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
    uint64_t m_bytes_written;
    std::shared_ptr<FILE> m_ofp;
    std::vector<uint32_t> m_chanmap;
    AudioStreamBasicDescription m_asbd;
public:
    WaveMuxer(std::shared_ptr<FILE> &ofp,
	      const AudioStreamBasicDescription &asbd,
	      const AudioChannelLayout *acl)
	: m_chanmask(0),
	  m_data_pos(0),
	  m_bytes_written(0),
	  m_ofp(ofp),
	  m_asbd(asbd)
    {
	struct stat stb = { 0 };
	if (fstat(_fileno(m_ofp.get()), &stb))
	    util::throw_crt_error("fstat()");
	m_seekable = ((stb.st_mode & S_IFMT) == S_IFREG);

	if (acl) {
	    std::vector<char> ichannels, ochannels;
	    chanmap::getChannels(acl, &ichannels);
	    chanmap::convertFromAppleLayout(ichannels, &ochannels);
	    m_chanmask = chanmap::getChannelMask(ochannels);
	    chanmap::getMappingToUSBOrder(ochannels, &m_chanmap);
	}
	std::string header = buildHeader();

	uint32_t hdrsize = header.size();
	write("RIFF\0\0\0\0WAVEfmt ", 16);
	write(&hdrsize, 4);
	write(header.c_str(), hdrsize);
	write("data\0\0\0\0", 8);
	m_data_pos = 28 + hdrsize;
    }
    ~WaveMuxer()
    {
	finishWrite();
    }
    void writeSamples(const void *data, size_t nsamples)
    {
	size_t nbytes = nsamples * m_asbd.mBytesPerFrame;
	if (!m_chanmap.size())
	    write(data, nbytes);
	else {
	    const uint8_t *bp = reinterpret_cast<const uint8_t*>(data);
	    uint32_t bpf = m_asbd.mBytesPerFrame;
	    uint32_t bpc = bpf / m_asbd.mChannelsPerFrame;
	    for (size_t i = 0; i < nsamples; ++i, bp += bpf)
		for (size_t j = 0; j < m_chanmap.size(); ++j)
		    write(bp + bpc * (m_chanmap[j] - 1), bpc);
	}
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
	    m_asbd.mBitsPerChannel > 16)
	    format = 0xfffe; // WAVE_FORMAT_EXTENSIBLE
	put(sb, format);
	put(sb, static_cast<int16_t>(m_asbd.mChannelsPerFrame));
	put(sb, static_cast<int32_t>(m_asbd.mSampleRate));
	int32_t bytes_per_sec = m_asbd.mSampleRate * m_asbd.mBytesPerFrame;
	put(sb, bytes_per_sec);
	put(sb, static_cast<int16_t>(m_asbd.mBytesPerFrame));
	put(sb, static_cast<int16_t>(m_asbd.mBitsPerChannel));
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
	fpos_t pos = 0;
	if (riffsize64 >> 32 == 0 && !std::fgetpos(m_ofp.get(), &pos)) {
	    if (!std::fseek(m_ofp.get(), m_data_pos - 4, SEEK_SET)) {
		uint32_t size32 = static_cast<uint32_t>(datasize64);
		write(&size32, 4);
		if (!std::fseek(m_ofp.get(), 4, SEEK_SET)) {
		    uint32_t size32 = static_cast<uint32_t>(riffsize64);
		    write(&size32, 4);
		}
	    }
	}
    }
};

static
void process(const std::wstring &ifilename, std::shared_ptr<FILE> &ofp)
{
    CAFDecoder decoder(ifilename);
    WaveMuxer muxer(ofp, decoder.getOutputFormat(),
		    decoder.getChannelLayout());
    int percent = 0;
    try {
	uint64_t total = decoder.length();
	uint64_t samples_read = 0;
	uint32_t bpf = decoder.getOutputFormat().mBytesPerFrame;
	std::vector<uint8_t> buffer(4096 * bpf);
	size_t nsamples;
	while ((nsamples = decoder.readSamples(&buffer[0], 4096)) > 0) {
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
void set_dll_directories()
{
    SetDllDirectoryW(L"");
    DWORD sz = GetEnvironmentVariableW(L"PATH", 0, 0);
    std::vector<wchar_t> vec(sz);
    sz = GetEnvironmentVariableW(L"PATH", &vec[0], sz);
    std::wstring searchPaths(&vec[0], &vec[sz]);

    HKEY hKey;
    const wchar_t *subkey =
	L"SOFTWARE\\Apple Inc.\\Apple Application Support";
    if (SUCCEEDED(RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
				KEY_READ, &hKey))) {
	std::shared_ptr<HKEY__> hKeyPtr(hKey, RegCloseKey);
	DWORD size;
	if (SUCCEEDED(RegQueryValueExW(hKey, L"InstallDir", 0, 0, 0, &size))) {
	    std::vector<wchar_t> vec(size/sizeof(wchar_t));
	    if (SUCCEEDED(RegQueryValueExW(hKey, L"InstallDir", 0, 0,
			reinterpret_cast<LPBYTE>(&vec[0]), &size))) {
		std::wstringstream ss;
		ss << &vec[0] << L";" << searchPaths;
		searchPaths = ss.str();
	    }
	}
    }
    std::wstring dir = util::get_module_directory() + L"QTfiles";
    std::wstringstream ss;
    ss << dir << L";" << searchPaths;
    searchPaths = ss.str();
    SetEnvironmentVariableW(L"PATH", searchPaths.c_str());
}

static
FARPROC WINAPI dll_failure_hook(unsigned notify, PDelayLoadInfo pdli)
{
    util::throw_win32_error(pdli->szDll, pdli->dwLastError);
    return 0;
}

void usage()
{
    std::fwprintf(stderr, L"usage: cafdec INFILE [OUTFILE]\n");
    std::exit(1);
}

int wmain(int argc, wchar_t **argv)
{
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF|_CRTDBG_CHECK_ALWAYS_DF);
#endif
    _setmode(2, _O_U8TEXT);
    std::setbuf(stderr, 0);

    if (argc < 2)
	usage();
    try {
        set_dll_directories();
	__pfnDliFailureHook2 = dll_failure_hook;
	std::wstring ofilename;
	if (argc > 2)
	    ofilename = argv[2];
	else {
	    std::wstring basename = PathFindFileNameW(argv[1]);
	    ofilename =
		util::PathReplaceExtension(basename, L"wav");
	}
	std::shared_ptr<FILE> ofp;
	if (ofilename != L"-")
	    ofp = util::open_file(ofilename, L"wb");
	else {
	    _setmode(1, _O_BINARY);
	    std::setbuf(stdout, 0);
	    struct Lambda { static void call(FILE *fp) {} };
	    ofp = std::shared_ptr<FILE>(stdout, Lambda::call);
	}
	process(argv[1], ofp);
	return 0;
    } catch (const std::exception & e) {
	std::fwprintf(stderr, L"ERROR: %s\n",
		 strutil::m2w(e.what(), utf8_codecvt_facet()));
	return 2;
    }
}
