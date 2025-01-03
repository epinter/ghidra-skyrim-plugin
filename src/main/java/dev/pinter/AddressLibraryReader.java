/*
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package dev.pinter;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class AddressLibraryReader {
    private final Map<Long, Long> data = new LinkedHashMap<>();
    private File offsetsDir;
    private String version;
    private Game game = Game.Undefined;
    private boolean offsetAsKey;
    private String binGameFilename = "";
    private long imageBase = 0;
    private boolean useImageBase = false;

    public enum BinFormat {
        Unknown(0),
        SSEv1(1),
        SSEv2(2);

        BinFormat(int format) {
            this.format = format;
        }

        private final int format;

        public int get() {
            return format;
        }

        public static BinFormat fromNumber(int v) {
            switch (v) {
                case 1 -> {
                    return SSEv1;
                }
                case 2 -> {
                    return SSEv2;
                }
                default -> {
                    return Unknown;
                }
            }
        }
    }

    public enum Game {
        Undefined,
        Skyrim,
        SkyrimSE,
        SkyrimAE,
        Starfield,
        Fallout4,
        SkyrimVR,
        Fallout4VR
    }

    public long getOffsetById(long id) {
        Long offset = data.get(id);
        if (offset != null) {
            return offset;
        }
        return 0;
    }

    public long getIdByOffset(long offset) {
        List<Long> list = data.entrySet().stream().filter(f -> f.getValue() == offset).map(Map.Entry::getKey).toList();
        if (list.size() == 1 && list.getFirst() != null) {
            return list.getFirst();
        } else if (list.size() > 1) {
            throw new IllegalStateException("More than one entry found");
        } else {
            return 0;
        }
    }

    public String getGameFilename() {
        return binGameFilename;
    }

    public static Builder newBuilder() {
        return new AddressLibraryReader().new Builder();
    }

    public class Builder {
        public Builder withImageBase(long imageBase) {
            AddressLibraryReader.this.imageBase = imageBase;
            if (imageBase > 0) {
                AddressLibraryReader.this.useImageBase = true;
            }
            return this;
        }

        public Builder withImageBase(boolean imageBase) {
            AddressLibraryReader.this.useImageBase = imageBase;
            AddressLibraryReader.this.imageBase = 0x140000000L;
            return this;
        }

        public Builder withOffsetAsKey(boolean offsetAsKey) {
            AddressLibraryReader.this.offsetAsKey = offsetAsKey;
            return this;
        }

        public Builder withDirectory(Path path) {
            AddressLibraryReader.this.offsetsDir = path.toFile();
            return this;
        }

        public Builder withGame(Game game) {
            AddressLibraryReader.this.game = game;
            return this;
        }

        public Builder withVersion(String version) {
            if (version == null) {
                throw new IllegalArgumentException("Invalid version");
            }

            String[] versionNumbers = version.split("[-.]");
            if (versionNumbers.length == 4) {
                AddressLibraryReader.this.version = String.format("%s-%s-%s-%s",
                        versionNumbers[0], versionNumbers[1], versionNumbers[2], versionNumbers[3]);
            } else if (versionNumbers.length == 5) {
                AddressLibraryReader.this.version = String.format("%s-%s-%s-%s-%s",
                        versionNumbers[0], versionNumbers[1], versionNumbers[2], versionNumbers[3], versionNumbers[4]);
            } else {
                throw new IllegalArgumentException("Invalid version");
            }
            return this;
        }

        public AddressLibraryReader build() throws IOException {
            String nameV1 = String.format("version-%s.bin", version);
            String nameV2 = String.format("versionlib-%s.bin", version);
            String nameVR = String.format("version-%s.csv", version);

            if (game.equals(Game.Skyrim) && Path.of(offsetsDir.toString(), nameV1).toFile().exists()) {
                game = Game.SkyrimSE;
            } else if (game.equals(Game.Skyrim) && Path.of(offsetsDir.toString(), nameV2).toFile().exists()) {
                game = Game.SkyrimAE;
            }

            switch (game) {
                case SkyrimSE -> readSseBin(Path.of(offsetsDir.toString(), nameV1));

                case SkyrimAE, Starfield -> readSseBin(Path.of(offsetsDir.toString(), nameV2));

                case Fallout4 -> readFallout4Bin(Path.of(offsetsDir.toString(), nameV1));

                case SkyrimVR, Fallout4VR -> readCsvVR(Path.of(offsetsDir.toString(), nameVR));

                default -> throw new IOException(String.format("Invalid game (%s)", game));
            }
            return AddressLibraryReader.this;
        }
    }

    private void readSseBin(Path fileName) throws IOException {
        File bin = fileName.toFile();
        if (!bin.exists() || bin.length() == 0) {
            throw new IOException("Invalid file");
        }
        try (FileChannel channel = FileChannel.open(fileName, StandardOpenOption.READ)) {
            MappedByteBuffer map = channel.map(FileChannel.MapMode.READ_ONLY, 0, bin.length());
            map.order(ByteOrder.LITTLE_ENDIAN);

            BinFormat format = BinFormat.fromNumber(map.getInt());

            if (format.equals(BinFormat.Unknown)) {
                throw new IOException("Error reading version.bin, format " + format);
            }

            if ((format.equals(BinFormat.SSEv2) && !bin.getName().startsWith("versionlib-")) ||
                    (format.equals(BinFormat.SSEv1) && !bin.getName().startsWith("version-"))) {
                throw new IOException(String.format("Error reading version.bin, format %s with invalid filename", format));
            }

            String binVersion = String.format("%s-%s-%s-%s", map.getInt(), map.getInt(), map.getInt(), map.getInt());
            String[] gvNum = version.split("[.-]");
            String gameVersion = String.format("%s-%s-%s-%s", gvNum[0], gvNum[1], gvNum[2], gvNum[3]);
            if (!binVersion.equals(gameVersion)) {
                throw new IOException(String.format("Error reading version.bin. Format %s with invalid version: found '%s', expected '%s'",
                        format, binVersion, gameVersion));
            }

            String gameBinaryName = "";
            int filenameLen = map.getInt();
            if (filenameLen < 0 || filenameLen >= 0x10000) {
                throw new IOException("Invalid version.bin");
            } else if (filenameLen > 0) {
                byte[] bufFilename = new byte[filenameLen];
                map.get(bufFilename);
                gameBinaryName = new String(bufFilename, StandardCharsets.UTF_8);
            }

            int ptrSize = map.getInt();
            int addrCount = map.getInt();

            int type;
            int low;
            int high;
            int b1, b2;
            int w1, w2;
            long d1, d2;
            long q1, q2;
            long pvid = 0, poffset = 0, tpoffset;

            for (int i = 0; i < addrCount; i++) {
                type = readUnsignedByte(map);
                low = type & 0xF;
                high = type >> 4;

                switch (low) {
                    case 0 -> q1 = map.getLong();
                    case 1 -> q1 = pvid + 1;
                    case 2 -> {
                        b1 = readUnsignedByte(map);
                        q1 = pvid + b1;
                    }
                    case 3 -> {
                        b1 = readUnsignedByte(map);
                        q1 = pvid - b1;
                    }
                    case 4 -> {
                        w1 = readUnsignedShort(map);
                        q1 = pvid + w1;
                    }
                    case 5 -> {
                        w1 = readUnsignedShort(map);
                        q1 = pvid - w1;
                    }
                    case 6 -> {
                        w1 = readUnsignedShort(map);
                        q1 = w1;
                    }
                    case 7 -> {
                        d1 = readUnsignedInt(map);
                        q1 = d1;
                    }
                    default -> {
                        return;
                    }
                }

                tpoffset = (high & 8) != 0 ? (poffset / (long) ptrSize) : poffset;

                switch (high & 7) {
                    case 0 -> q2 = map.getLong();
                    case 1 -> q2 = tpoffset + 1;
                    case 2 -> {
                        b2 = readUnsignedByte(map);
                        q2 = tpoffset + b2;
                    }
                    case 3 -> {
                        b2 = readUnsignedByte(map);
                        q2 = tpoffset - b2;
                    }
                    case 4 -> {
                        w2 = readUnsignedShort(map);
                        q2 = tpoffset + w2;
                    }
                    case 5 -> {
                        w2 = readUnsignedShort(map);
                        q2 = tpoffset - w2;
                    }
                    case 6 -> {
                        w2 = readUnsignedShort(map);
                        q2 = w2;
                    }
                    case 7 -> {
                        d2 = readUnsignedInt(map);
                        q2 = d2;
                    }
                    default -> throw new IOException("error reading version.bin");
                }

                if ((high & 8) != 0)
                    q2 *= ptrSize;

                long offset = q2;
                if (useImageBase) {
                    offset += imageBase;
                }

                if (offsetAsKey) {
                    data.put(offset, q1);
                } else {
                    data.put(q1, offset);
                }
                poffset = q2;
                pvid = q1;
            }
            this.binGameFilename = gameBinaryName;
        } catch (IOException e) {
            data.clear();
            throw e;
        }
    }

    private void readFallout4Bin(Path fileName) throws IOException {
        File bin = fileName.toFile();
        if (!bin.exists() || bin.length() == 0) {
            throw new IOException("Invalid file");
        }

        try (FileChannel channel = FileChannel.open(fileName, StandardOpenOption.READ)) {
            MappedByteBuffer map = channel.map(FileChannel.MapMode.READ_ONLY, 0, bin.length());
            map.order(ByteOrder.LITTLE_ENDIAN);

            long count = map.getLong();
            while (map.hasRemaining()) {
                long id = map.getLong();
                long offset = map.getLong();
                if (useImageBase) {
                    data.put(id, offset + imageBase);
                } else {
                    data.put(id, offset);
                }
            }
            if (data.size() != count) {
                data.clear();
                throw new IOException("Error reading version.bin");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void readCsvVR(Path fileName) throws IOException {
        try (BufferedReader csv = Files.newBufferedReader(fileName)) {
            String[] header = csv.lines().skip(1).findFirst().orElse("0,0").split(",");
            int size = Integer.parseInt(header[0]);
            String csvVersion = header[1];
            AtomicInteger count = new AtomicInteger();

            csv.lines()
                    .map(f -> Arrays.asList(f.split(",")))
                    .forEach(l -> {
                        count.incrementAndGet();
                        try {
                            long id = Long.parseLong(l.getFirst());
                            long offset = Long.parseLong(l.get(1), 16);
                            if (id > 0 && offset > 0) {
                                data.put(id, offset);
                            }
                        } catch (NumberFormatException ignore) {
                        }
                    });
            if (size != count.get()) {
                throw new IOException("Error reading csv, number of lines didn't match. Version " + csvVersion);
            }
        }
    }

    private static long readUnsignedInt(MappedByteBuffer buffer) {
        return buffer.getInt() & 0xFFFFFFFFL;
    }

    private static int readUnsignedByte(MappedByteBuffer buffer) {
        return buffer.get() & 0xFF;
    }

    private static int readUnsignedShort(MappedByteBuffer buffer) {
        return buffer.getShort() & 0xFFFF;
    }
}
