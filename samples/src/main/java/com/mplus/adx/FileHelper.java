package com.mplus.adx;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class FileHelper {
	public static ArrayList<String> readLines(String filePath, String encoding) throws IOException {
		ArrayList<String> lines = new ArrayList<>();
		try (FileInputStream input = new FileInputStream(filePath);
				InputStreamReader reader = new InputStreamReader(input, encoding);
				BufferedReader br = new BufferedReader(reader);) {
			String line = null;
			while ((line = br.readLine()) != null) {
				lines.add(line);
			}
		}
		return lines;
	}

	/**
	 * 读取指定路径文件中所有的字节
	 * 
	 * @param filePath
	 *            被读取的文件路径
	 * @return 读取的文件中的所有字节
	 * @throws IOException
	 */
	public static byte[] readBytes(String filePath) throws IOException {
		byte[] result = null;
		try (FileInputStream inputStream = new FileInputStream(filePath)) {
			try (ByteArrayOutputStream outStream = new ByteArrayOutputStream()) {
				byte[] data = new byte[1024];
				int count = -1;
				while ((count = inputStream.read(data)) != -1) {
					outStream.write(data, 0, count);
				}

				data = null;
				result = outStream.toByteArray();
				outStream.flush();
			}
		}
		return result;
	}

	public static List<String> getAllFileAbsolutePath(String path, final boolean recursive, FileFilter filter) {
		File dir = new File(path);
		// 如果不存在或者 也不是目录就直接返回
		if (!dir.exists() || !dir.isDirectory()) {
			return null;
		}
		List<String> filePaths = new ArrayList<>();
		File[] dirfiles = dir.listFiles(filter);
		for (File file : dirfiles) {
			// 如果是目录 则继续扫描
			if (file.isDirectory()) {
				getAllFileAbsolutePath(file.getAbsolutePath(), recursive, filter);
			} else {
				// 如果是java类文件 去掉后面的.class 只留下类名
				filePaths.add(file.getAbsolutePath());
			}
		}

		return filePaths;
	}
}
