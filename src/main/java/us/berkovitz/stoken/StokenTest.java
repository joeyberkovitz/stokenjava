package us.berkovitz.stoken;

import java.io.File;
import java.util.Scanner;

public class StokenTest {
	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		System.out.print("File Name: ");
		String fileName = scanner.nextLine();
		File tokenFile = new File(fileName);
		SecurIdToken token1 = SecurIdToken.Companion.importFile(tokenFile);
		String pass1 = "";
		if(token1.passRequired()){
			System.out.print("Pass: ");
			pass1 = scanner.nextLine();
			token1.decryptSeed(pass1, "");
		}
		System.out.println(token1.computeTokenCode(System.currentTimeMillis() / 1000, ""));
		System.out.println(token1.passRequired());


		System.out.print("Token: ");
		String tokenStr = scanner.nextLine();
		SecurIdToken token = SecurIdToken.Companion.importString(tokenStr, false);

		String guidVal = "";
		System.out.println("DevID Required: " + token.devIdRequired());
		if(token.devIdRequired()){
			for(TokenGUID guid: TokenGUID.values()){
				System.out.println("Trying GUID: " + guid.getGuid());
				if(token.checkDevId(guid.getGuid())) {
					guidVal = guid.getGuid();
					break;
				}
				else
					System.out.println("GUID failed");
			}
		}

		String pass = "";
		if(token.passRequired()) {
			System.out.print("Pass: ");
			pass = scanner.nextLine();
		}
		token.decryptSeed(pass, guidVal);

		String pin = "";
		if(token.pinRequired()) {
			System.out.print("Pin: ");
			pin = scanner.nextLine();
		}


		String code = token.computeTokenCode(System.currentTimeMillis() / 1000, pin);
		System.out.println("Code: " + code);

		String encodedToken = token.encodeToken(pass, guidVal, 2);
		System.out.println("Encoded token: " + encodedToken);



	}
}
