package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class Converter {

	public static String encode(Element e) {
		return Base64.getEncoder().encodeToString(e.toBytes());
	}
	

	public static String encodeObject(Object m)  throws IOException{
		// Convert Map to byte array		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;  
		try{
			out = new ObjectOutputStream(bos);
			out.writeObject(m);
			out.flush();
			byte[] mapBytes = bos.toByteArray();
			return Base64.getEncoder().encodeToString(mapBytes);
		} 
		finally {
			try {
				bos.close();
			} catch (IOException ex) {
			// ignore close exception
			}
		}
	}

	static String encode1dList(List<Element> l) {
		JSONArray ja = new JSONArray();
		for(int j=0; j<l.size(); j++) {
			ja.put(encode(l.get(j)));
		}
		return ja.toString();
	}
	
	static String encode2dList(List<List<Element>> L) throws JSONException {
		JSONArray JA = new JSONArray();
		for(int i=0; i<L.size(); i++) {
			JSONArray ja = new JSONArray(encode1dList(L.get(i)));
			JA.put(i,ja);
		}
		return JA.toString();
	}
	
	static int[] jsonToIntArray(JSONArray ja) throws JSONException {
		int[] a = new int[ja.length()];
		for (int i = 0; i < ja.length(); i++) {
			a[i] = ja.getInt(i);
		}
		return a;
	}

	@SuppressWarnings("rawtypes")
	public static Element decode(String string, Field F) {
		Element e = F.newElement();
		e.setFromBytes(Base64.getDecoder().decode(string));
		return e;
	}
	

	public static Object decodeObject(String string) throws IOException{
		ByteArrayInputStream bis = new ByteArrayInputStream(Base64.getDecoder().decode(string));
		ObjectInput in = null;
		try {
			in = new ObjectInputStream(bis);
			Object m = in.readObject(); 
			return m;
		} catch (ClassNotFoundException e) { 
			return null;
		}
		finally {
			try {
				if (in != null) {
					in.close();
				}
			} catch (IOException ex) {
				// ignore close exception
			}
		}		
	}

	@SuppressWarnings("rawtypes")
	public static List<Element> decode1dList(String string, Field F) throws JSONException {
		JSONArray ja = new JSONArray(string);
		List<Element> l = new ArrayList<Element>();
		for(int j=0; j<ja.length(); j++) {
			l.add(decode(ja.getString(j),F));
		}
		return l;
	} 
	
	@SuppressWarnings("rawtypes")
	public static List<List<Element>> decode2dList(String string, Field F) throws JSONException {
		List<List<Element>> L = new ArrayList<List<Element>>();
		JSONArray JA = new JSONArray(string);
		for(int i=0; i<JA.length(); i++) {
			List<Element> l = decode1dList(JA.get(i).toString(),F);
			L.add(l);
		}
		return L;
	} 
}
