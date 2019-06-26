import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ItemDeserializer {
	static final long MAGIC_NUMBER = 0x2e30212634e92c20L;
	static final int FORMAT_VERSION = 1;
	static final String ZIP_ENTRY_NAME = "FOLDER_ITEM";
	static final int IO_BUFFER_SIZE = 32 * 1024;

	private InputStream packedFile;
	private String itemName;
	private String contentType;
	private int fileType;
	private long length;

	private boolean saved = false;

	public ItemDeserializer(File packedFile) throws IOException {
		this(new FileInputStream(packedFile));
	}

	public ItemDeserializer(InputStream input) throws IOException {
		this.packedFile = input;
		
		// Read header containing: original item name and content type
		boolean success = false;
		try {
			ObjectInputStream objIn = new ObjectInputStream(packedFile);
			if (objIn.readLong() != MAGIC_NUMBER) {
				throw new IOException("Invalid data");
			}
			if (objIn.readInt() != FORMAT_VERSION) {
				throw new IOException("Unsupported data format");
			}

			itemName = objIn.readUTF();
			contentType = objIn.readUTF();
			if (contentType.length() == 0) {
				contentType = null;
			}
			fileType = objIn.readInt();
			length = objIn.readLong();
			success = true;
		}
		catch (UTFDataFormatException e) {
			throw new IOException("Invalid item data");
		}
		finally {
			if (!success) {
				try {
					packedFile.close();
				}
				catch (IOException e) {
				}
			}
		}
	}

	@Override
	protected void finalize() throws Throwable {
		dispose();
		super.finalize();
	}

	public void dispose() {
		if (packedFile != null) {
			try {
				packedFile.close();
			}
			catch (IOException e) {
			}
			finally {
				packedFile = null;
			}
		}
	}

	public String getItemName() {
		return itemName;
	}

	public String getContentType() {
		return contentType;
	}

	public int getFileType() {
		return fileType;
	}

	public long getLength() {
		return length;
	}

	public void saveItem(OutputStream out) throws IOException {

		if (saved) {
			throw new IllegalStateException("Already saved");
		}
		saved = true;

		ZipInputStream zipIn = new ZipInputStream(packedFile);
		ZipEntry entry = zipIn.getNextEntry();
		if (entry == null || !ZIP_ENTRY_NAME.equals(entry.getName())) {
			throw new IOException("Data error");
		}

		InputStream itemIn = zipIn;
		long len = length;
		byte[] buffer = new byte[IO_BUFFER_SIZE];

		// Copy file contents
		int cnt = (int) (len < IO_BUFFER_SIZE ? len : IO_BUFFER_SIZE);
		while ((cnt = itemIn.read(buffer, 0, cnt)) > 0) {
			out.write(buffer, 0, cnt);
			len -= cnt;
			cnt = (int) (len < IO_BUFFER_SIZE ? len : IO_BUFFER_SIZE);
		}

	}
	
	public static void main(String[] args) throws IOException {
		System.out.println("input: " + args[0]);  
		System.out.println("output: " + args[1]);
		
		File input = new File(args[0]);
		File output = new File(args[1]);
		
		ItemDeserializer x = new ItemDeserializer(input);
		x.saveItem(new FileOutputStream(output));		
	}

}
