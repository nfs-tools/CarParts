#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <boost/filesystem.hpp>

#include "BitConverter.h"
#include "JDLZ.h"

namespace fs = boost::filesystem;

std::vector<size_t> getOccurrences(const std::string &haystack, const std::string &needle)
{
    std::vector<size_t> positions; // holds all the positions that sub occurs within str

    size_t pos = haystack.find(needle, 0);
    while (pos != std::string::npos)
    {
        positions.push_back(pos);
        pos = haystack.find(needle, pos + 1);
    }

    return positions;
}

void hexdump(FILE *stream, void const *data, size_t len)
{
    unsigned int i;
    unsigned int r, c;

    if (stream == nullptr)
        return;
    if (data == nullptr)
        return;

    for (r = 0, i = 0; r < (len / 16 + static_cast<unsigned int>(len % 16 != 0)); r++, i += 16)
    {
        fprintf(stream, "%04X:   ", i); /* location of first byte in line */

        for (c = i; c < i + 8; c++) /* left half of hex dump */
            if (c < len)
                fprintf(stream, "%02X ", ((unsigned char const *) data)[c]);
            else
                fprintf(stream, "   "); /* pad if short line */

        fprintf(stream, "  ");

        for (c = i + 8; c < i + 16; c++) /* right half of hex dump */
            if (c < len)
                fprintf(stream, "%02X ", ((unsigned char const *) data)[c]);
            else
                fprintf(stream, "   "); /* pad if short line */

        fprintf(stream, "   ");

        for (c = i; c < i + 16; c++) /* ASCII dump */
            if (c < len)
                if (((unsigned char const *) data)[c] >= 32 &&
                    ((unsigned char const *) data)[c] < 127)
                    fprintf(stream, "%c", ((char const *) data)[c]);
                else
                    fprintf(stream, "."); /* put this for non-printables */
            else
                fprintf(stream, " "); /* pad if short line */

        fprintf(stream, "\n");
    }

    fflush(stream);
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        std::cout << "Usage: " << argv[0] << " <car data folder>" << std::endl;
        return 1;
    }

    const std::string &carDirectory = argv[1];

    fs::path carDir = fs::absolute(carDirectory);

    if (!fs::is_directory(carDir))
    {
        std::cout << "Couldn't find: " << carDir.string() << std::endl;
        return 1;
    }

    fs::path texturesFile = carDir / "TEXTURES.bin";
    fs::path geometryFile = carDir / "GEOMETRY.bin";

    if (!fs::exists(texturesFile))
    {
        std::cout << "Couldn't find TEXTURES.bin: " << carDir.string() << std::endl;
        return 1;
    }

    if (!fs::exists(geometryFile))
    {
        std::cout << "Couldn't find GEOMETRY.bin: " << carDir.string() << std::endl;
        return 1;
    }

    std::ios::fmtflags flags(std::cout.flags());

    {
        /**
         * TEXTURES.bin parsing
         * Known info:
         * - TEXTURES.bin is 1 large BCHUNK_SPEED_TEXTURE_PACK_LIST_CHUNKS chunk (0xB3300000)
         * - Multiple JDLZ compressed blocks, presumably for each texture entry
         */

        std::ifstream texturesStream(texturesFile.string(), std::ios::binary);
        std::vector<unsigned char> magicBytes = {
                0x02, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x01, 0x00, 0x00, 0x00
        };

        std::vector<std::pair<std::string, std::string>> textureNames;

        uint32_t type;
        uint32_t size;

        texturesStream.read((char *) &type, sizeof(type));
        assert(type == 0xB3300000);
        texturesStream.read((char *) &size, sizeof(size));

//        std::cout << "Size: " << size << std::endl;

        std::vector<unsigned char> allData;
        allData.resize(size);
        texturesStream.read((char *) &allData[0], allData.size());

        texturesStream.seekg(8);

        unsigned char header[0x4c]; // 76 bytes
        unsigned char name[0x5c]; // 92 bytes; end-of-string padded by NULs

        texturesStream.read((char *) &header[0], sizeof(header));
        texturesStream.read((char *) &name[0], sizeof(name));

        std::string nameStr(name, name + sizeof(name));
        {
            auto firstNull = nameStr.find_first_of((char) '\0');
            auto lastAscii = nameStr.find_last_of(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.");
            nameStr = nameStr.substr(0, lastAscii + 1);
            nameStr = nameStr.substr(firstNull + 1);
        }

        std::cout << "Name: " << nameStr << std::endl;

        std::string vecStr(allData.begin(),
                           allData.end());
        std::vector<size_t> jdlzOccurrences = getOccurrences(vecStr, "JDLZ");

        for (int i = 0; i < jdlzOccurrences.size(); i++)
        {
            size_t pos = jdlzOccurrences[i];
//            std::cout << "JDLZ block #" << i + 1 << " @ " << pos << std::endl;

            texturesStream.seekg(pos + 8);

            {
                unsigned char jdlz[5]; // JDLZ + 0x02
                texturesStream.read((char *) &jdlz[0], sizeof(jdlz));

                assert(jdlz[0] == 'J' && jdlz[1] == 'D' && jdlz[2] == 'L' && jdlz[3] == 'Z' && jdlz[4] == 0x02);
            }

            {
                unsigned char pl[1];
                texturesStream.read((char *) &pl[0], sizeof(pl));
                assert(pl[0] == 0x10);
            }

            {
                unsigned char z_[2];
                texturesStream.read((char *) &z_[0], sizeof(z_));
                int16_t z = BitConverter::ToInt16(z_, 0);

                assert(z == 0x0000);
            }

            size_t uncompressedLength;
            size_t compressedLength;

            unsigned char uncompressedLength_[4];
            unsigned char compressedLength_[4];

            texturesStream.read((char *) &uncompressedLength_[0], sizeof(uncompressedLength_));
            texturesStream.read((char *) &compressedLength_[0], sizeof(compressedLength_));

            uncompressedLength = static_cast<size_t>(BitConverter::ToInt32(uncompressedLength_, 0));
            compressedLength = static_cast<size_t>(BitConverter::ToInt32(compressedLength_, 0));

//            std::cout << uncompressedLength << " / " << compressedLength << std::endl;

            texturesStream.seekg(pos + 8);

            std::vector<BYTE> compressed;
            compressed.resize(compressedLength);

            texturesStream.read((char *) &compressed[0], compressed.size());

            std::vector<BYTE> uncompressed = JDLZ::decompress(compressed);
            assert(uncompressed.size() == uncompressedLength);

            const unsigned char *ucData = uncompressed.data();

            std::string uncompressedStr(ucData, ucData + uncompressedLength);

            fs::path uncompressedPath = carDir / ("UncompressedTexturesChunk-" + std::to_string(i + 1) + ".data");
            fs::path hexPath = carDir / ("UncompressedTexturesChunk-" + std::to_string(i + 1) + ".hex");
            FILE *dumpFile = fopen(uncompressedPath.string().c_str(), "wb");
            FILE *hexFile = fopen(hexPath.string().c_str(), "w");
            fwrite(uncompressed.data(), uncompressed.size(), 1, dumpFile);
            hexdump(hexFile, uncompressed.data(), uncompressed.size());

            std::vector<size_t> dxtOccurrences = getOccurrences(uncompressedStr, "DXT");

            for (size_t dxtPos : dxtOccurrences)
            {
                std::vector<unsigned char> subvec((uncompressed.begin() + dxtPos) - 48,
                                                  (uncompressed.begin() + dxtPos) + 4);
                std::stringstream nameStream;
                std::stringstream formatStream;

                for (int j = 0; j < 48; j++)
                {
                    unsigned char c = subvec[j];

                    if (c == 0x23 || c == 0x17)
                    {
                        continue;
                    }

                    if (c >= 32 && c < 127)
                    {
                        nameStream << c;
                    }
                }

                for (int j = 48; j < 52; j++)
                {
                    formatStream << subvec[j];
                }

                textureNames.emplace_back(std::make_pair(nameStream.str(), formatStream.str()));
            }
        }

        std::cout << "Car Texture List (" << textureNames.size() << "):" << std::endl;

        for (int i = 0; i < textureNames.size(); i++)
        {
            auto pair = textureNames[i];

            std::cout << "#" << (i + 1) << ": " << pair.first << " - compression type: " << pair.second << std::endl;
        }
    }

    std::cout << std::endl;

    {
        /**
         * GEOMETRY.bin parsing
         * Known info: More than TEXTURES.bin
         */

        std::ifstream geometryStream(geometryFile.string(), std::ios::binary);
        std::vector<std::string> geometryPartNames; // ( ͡° ͜ʖ ͡°)

        uint32_t type;
        uint32_t size;

        geometryStream.read((char *) &type, sizeof(type));
        assert(type == 0x80134000);
        geometryStream.read((char *) &size, sizeof(size));

//        std::cout << "Size: " << size << std::endl;

        std::vector<unsigned char> allData;
        allData.resize(size);
        geometryStream.read((char *) &allData[0], allData.size());

        geometryStream.seekg(8);

        std::string vecStr(allData.begin(),
                           allData.end());
        std::vector<size_t> jdlzOccurrences = getOccurrences(vecStr, "JDLZ");

        for (int i = 0; i < jdlzOccurrences.size(); i++)
        {
            size_t pos = jdlzOccurrences[i];
//            std::cout << "JDLZ block #" << i + 1 << " @ " << pos << std::endl;

            geometryStream.seekg(pos + 8);

            {
                unsigned char jdlz[5]; // JDLZ + 0x02
                geometryStream.read((char *) &jdlz[0], sizeof(jdlz));

                assert(jdlz[0] == 'J' && jdlz[1] == 'D' && jdlz[2] == 'L' && jdlz[3] == 'Z' && jdlz[4] == 0x02);
            }

            {
                unsigned char pl[1];
                geometryStream.read((char *) &pl[0], sizeof(pl));
                assert(pl[0] == 0x10);
            }

            {
                unsigned char z_[2];
                geometryStream.read((char *) &z_[0], sizeof(z_));
                int16_t z = BitConverter::ToInt16(z_, 0);

                assert(z == 0x0000);
            }

            size_t uncompressedLength;
            size_t compressedLength;

            unsigned char uncompressedLength_[4];
            unsigned char compressedLength_[4];

            geometryStream.read((char *) &uncompressedLength_[0], sizeof(uncompressedLength_));
            geometryStream.read((char *) &compressedLength_[0], sizeof(compressedLength_));

            uncompressedLength = static_cast<size_t>(BitConverter::ToInt32(uncompressedLength_, 0));
            compressedLength = static_cast<size_t>(BitConverter::ToInt32(compressedLength_, 0));

//            std::cout << uncompressedLength << " / " << compressedLength << std::endl;

            geometryStream.seekg(pos + 8);

            std::vector<BYTE> compressed;
            compressed.resize(compressedLength);

            geometryStream.read((char *) &compressed[0], compressed.size());

            std::vector<BYTE> uncompressed = JDLZ::decompress(compressed);
            assert(uncompressed.size() == uncompressedLength);

            fs::path uncompressedPath = carDir / ("UncompressedGeometryChunk-" + std::to_string(i + 1) + ".data");
            fs::path hexPath = carDir / ("UncompressedGeometryChunk-" + std::to_string(i + 1) + ".hex");
            FILE *dumpFile = fopen(uncompressedPath.string().c_str(), "wb");
            FILE *hexFile = fopen(hexPath.string().c_str(), "w");
            fwrite(uncompressed.data(), uncompressed.size(), 1, dumpFile);
            hexdump(hexFile, uncompressed.data(), uncompressed.size());

            const unsigned char *uncompressedUC = uncompressed.data();

            if (uncompressedUC[0] == 0x10 && uncompressedUC[1] == 0x40 && uncompressedUC[2] == 0x13 &&
                uncompressedUC[3] == 0x80)
            {
//                std::cout << "This one has a part!" << std::endl;
                std::stringstream partNameStream;

                for (int j = 0x000000B0;; j++)
                {
                    if (uncompressedUC[j] >= 32 && uncompressedUC[j] < 127)
                    {
                        partNameStream << uncompressedUC[j];
                    } else
                    {
                        break;
                    }
                }

                geometryPartNames.emplace_back(partNameStream.str());
            }
        }

        std::sort(geometryPartNames.begin(), geometryPartNames.end());

        std::cout << "Car Part List (" << geometryPartNames.size() << "):" << std::endl;

        for (int i = 0; i < geometryPartNames.size(); i++)
        {
            std::cout << "#" << (i + 1) << ": " << geometryPartNames[i] << std::endl;
        }
    }

    std::cout.flags(flags);

    return 0;
}