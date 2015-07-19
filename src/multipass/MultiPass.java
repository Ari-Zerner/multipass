/*
 * Multipass v2.1.2 Copyright 2015 Ari Zerner.
 * You may use and modify this software for any purpose, provided you do not
 * give credit for its creation to anyone but the copyright holder and you do
 * not give the copyright holder credit for any modifications for which he was
 * not responsible.
 */
package multipass;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.awt.font.TextAttribute;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.prefs.Preferences;
import javax.swing.*;
import javax.swing.Timer;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class MultiPass extends javax.swing.JFrame {

    private static final String VERSION = "v2.1.2",
            GENERATION_ALGORITHM = "SHA-256",
            CONFIRMATION_ALGORITHM = "SHA-256",
            PASSWORD_HEADER = "Mp2!",
            HEADER_MNEMONIC = "Multipass 2!",
            CONFIRMATION_HASH_KEY = "hash",
            CONFIRMATION_SALT_KEY = "salt",
            CLEAR_ENABLED_KEY = "enabled",
            CLEAR_TIME_KEY = "time";
    private static final int CONFIRMATION_HASH_LENGTH = 16,
            PASSWORD_LENGTH_WITHOUT_HEADER = 16, PIN_LENGTH = 4,
            MILLIS_PER_MINUTE = 60000;
    private char defaultEchoChar = '*';
    private Preferences preferences = Preferences.userRoot().node("multipass"),
            confirmPreferences = preferences.node("confirm"),
            clearTimerPreferences = preferences.node("clearTimer");
    private Timer clearTimer;

    /** Creates new form MultiPassGUI */
    public MultiPass() {
        initComponents();
        initClearTimer();
    }

    /**
     * Does the necessary setup for the clear timer.
     */
    private void initClearTimer() {
        clearTimer = new Timer(0,
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        masterField.setText("");
                        identifierField.setText("");
                        passwordField.setText("");
                        masterField.requestFocusInWindow();
                    }
                });

        clearTimer.setRepeats(false);

        Toolkit.getDefaultToolkit().addAWTEventListener(new AWTEventListener() {

            @Override
            public void eventDispatched(AWTEvent event) {
                if (clearCheckbox.isSelected()) {
                    clearTimer.restart();
                }
            }
        }, AWTEvent.MOUSE_EVENT_MASK | AWTEvent.KEY_EVENT_MASK);
        clearTimeSpinner.setValue(clearTimerPreferences.getInt(CLEAR_TIME_KEY,
                (Integer) clearTimeSpinner.getValue()));
        clearTimeSpinnerStateChanged(null);
        boolean clearEnabled = clearTimerPreferences.getBoolean(
                CLEAR_ENABLED_KEY, clearCheckbox.isSelected());
        clearCheckbox.setSelected(clearEnabled);
        if (clearEnabled) clearTimer.start();
    }

    /**
     * Generates a hash from text + " " + salt using the given algorithm.
     * @param text
     * @param salt
     * @param algorithm
     * @return the hash as a byte[]
     */
    private static byte[] generateHash(char[] text, String salt,
            String algorithm) {
        byte[] prehash = new byte[text.length + salt.length() + 1];
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        for (int i = 0; i < text.length; i++) {
            prehash[i] = (byte) text[i];
        }
        prehash[text.length] = ' ';
        for (int i = 0; i < salt.length(); i++) {
            prehash[i + text.length + 1] = (byte) salt.charAt(i);
        }
        byte[] hash = digest.digest(prehash);
        Arrays.fill(prehash, (byte) 0);
        return hash;
    }

    /**
     * Generates a password from a master password and an identifier.
     * @param master a secure password
     * @param identifier an identifier for the use of the password
     * @param length the desired password length
     */
    private static String generatePassword(char[] master, String identifier) {
        String password = PASSWORD_HEADER;
        password += printHexBinary(
                generateHash(master, identifier, GENERATION_ALGORITHM))
                .substring(0, PASSWORD_LENGTH_WITHOUT_HEADER).toLowerCase();
        return password;
    }

    /**
     * Generates a 4-digit PIN from a master password and an identifier.
     * @param master a secure password
     * @param identifier an identifier for the use of the password
     */
    private static String generatePIN(char[] master, String identifier) {
        int pin = new BigInteger(1,
                generateHash(master, identifier, GENERATION_ALGORITHM))
                .mod(BigInteger.TEN.pow(PIN_LENGTH)).intValue();
        return String.format("%04d", pin);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        masterField = new javax.swing.JPasswordField();
        jLabel2 = new javax.swing.JLabel();
        identifierField = new javax.swing.JTextField();
        passwordField = new javax.swing.JPasswordField();
        defaultEchoChar = passwordField.getEchoChar();
        copyPasswordButton = new javax.swing.JButton();
        clearClipboardButton = new javax.swing.JButton();
        aboutButton = new javax.swing.JButton();
        pinCheckBox = new javax.swing.JCheckBox();
        showCheckBox = new javax.swing.JCheckBox();
        confirmCheckBox = new javax.swing.JCheckBox();
        setConfirmButton = new javax.swing.JButton();
        clearTimeSpinner = new javax.swing.JSpinner();
        clearTimerMinutesLabel = new javax.swing.JLabel();
        clearCheckbox = new javax.swing.JCheckBox();
        jLabel3 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Multipass");

        jLabel1.setText("Master Password:");
        jLabel1.setToolTipText("");

        masterField.setToolTipText("Your master password.");
        masterField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                masterFieldActionPerformed(evt);
            }
        });
        masterField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                masterFieldKeyPressed(evt);
            }
            public void keyReleased(java.awt.event.KeyEvent evt) {
                masterFieldKeyReleased(evt);
            }
        });

        jLabel2.setText("Use Identifier:");

        identifierField.setToolTipText("An identifier you'll remember for this password or PIN (e.g. a website name). Pressing enter while this field is active will copy the generated password or PIN.");
        identifierField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                identifierFieldActionPerformed(evt);
            }
        });
        identifierField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                identifierFieldKeyPressed(evt);
            }
            public void keyReleased(java.awt.event.KeyEvent evt) {
                identifierFieldKeyReleased(evt);
            }
        });

        passwordField.setEditable(false);
        passwordField.setColumns(20);
        passwordField.setToolTipText("The generated password or PIN.");

        copyPasswordButton.setText("Copy Generated Password");
        copyPasswordButton.setToolTipText("Copy the generated password or PIN so it can be pasted where you need it. This can also be done by pressing enter when the \"Use Identifier\" field is active.");
        copyPasswordButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyPasswordButtonActionPerformed(evt);
            }
        });

        clearClipboardButton.setText("Clear Clipboard");
        clearClipboardButton.setToolTipText("Clear the clipboard so that the copied password or PIN can no longer be pasted.");
        clearClipboardButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                clearClipboardButtonActionPerformed(evt);
            }
        });

        aboutButton.setFont(aboutButton.getFont().deriveFont(new HashMap<TextAttribute, Integer>() {{put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);}}));
        aboutButton.setForeground(java.awt.Color.blue);
        aboutButton.setText("About Multipass");
        aboutButton.setToolTipText("");
        aboutButton.setBorder(null);
        aboutButton.setContentAreaFilled(false);
        aboutButton.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        aboutButton.setFocusPainted(false);
        aboutButton.setRequestFocusEnabled(false);
        aboutButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aboutButtonActionPerformed(evt);
            }
        });

        pinCheckBox.setText("Generate " + PIN_LENGTH + "-digit PIN");
        pinCheckBox.setToolTipText("Generate a " + PIN_LENGTH + "-digit PIN instead of a password.");
        pinCheckBox.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                pinCheckBoxStateChanged(evt);
            }
        });

        showCheckBox.setText("Show Generated Password");
        showCheckBox.setToolTipText("Show the generated password or PIN.");
        showCheckBox.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                showCheckBoxStateChanged(evt);
            }
        });

        confirmCheckBox.setSelected(true);
        confirmCheckBox.setText("Confirm Master Password");
        confirmCheckBox.setToolTipText("Ensure that you have typed your master password correctly. Recommended when creating a new password.");
        confirmCheckBox.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                confirmCheckBoxStateChanged(evt);
            }
        });

        setConfirmButton.setText("Set Confirmation Password");
        setConfirmButton.setToolTipText("Securely store a master password to be used when password confirmation is on.");
        setConfirmButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                setConfirmButtonActionPerformed(evt);
            }
        });

        clearTimeSpinner.setModel(new javax.swing.SpinnerNumberModel(Integer.valueOf(10), Integer.valueOf(1), null, Integer.valueOf(1)));
        clearTimeSpinner.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                clearTimeSpinnerStateChanged(evt);
            }
        });

        clearTimerMinutesLabel.setText("minutes of inactivity.");

        clearCheckbox.setSelected(true);
        clearCheckbox.setText("Clear all fields after");
        clearCheckbox.setToolTipText("Automatically clear the master password, use identifier, and generated password if you are inactive too long.");
        clearCheckbox.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                clearCheckboxStateChanged(evt);
            }
        });

        jLabel3.setText("Generated Password:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(passwordField))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(clearCheckbox)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(clearTimeSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(clearTimerMinutesLabel))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(confirmCheckBox)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(setConfirmButton)))
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(21, 21, 21)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(jLabel1)
                                    .addComponent(jLabel2))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(masterField)
                                    .addComponent(identifierField))))
                        .addContainerGap())
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(showCheckBox)
                            .addComponent(pinCheckBox))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(copyPasswordButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(clearClipboardButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(0, 0, Short.MAX_VALUE))))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(aboutButton)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(masterField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(identifierField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(showCheckBox)
                    .addComponent(copyPasswordButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(clearClipboardButton)
                    .addComponent(pinCheckBox))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(confirmCheckBox)
                    .addComponent(setConfirmButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(clearTimeSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(clearTimerMinutesLabel)
                    .addComponent(clearCheckbox))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(aboutButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void masterFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_masterFieldActionPerformed
        identifierField.requestFocusInWindow();
    }//GEN-LAST:event_masterFieldActionPerformed

    /**
     * Checks whether the master password fields are equal. If not, pops up a
     * message to inform the user.
     * @return whether the master password fields are equal
     */
    private boolean confirmMasterPassword() {
        String hash = confirmPreferences.get(CONFIRMATION_HASH_KEY, null),
                salt = confirmPreferences.get(CONFIRMATION_SALT_KEY, null);
        if (hash == null || salt == null) {
            return false;
        }
        char[] master = masterField.getPassword();
        boolean confirmed = printHexBinary(
                generateHash(master, salt, CONFIRMATION_ALGORITHM))
                .substring(0, CONFIRMATION_HASH_LENGTH).equals(hash);
        Arrays.fill(master, '\0');
        return confirmed;
    }

    /**
     * Generates a password (or PIN) and displays it in passwordField.
     */
    private void generate() {
        char[] master = masterField.getPassword();
        String identifier = identifierField.getText();
        if (master.length > 0) {
            if (!confirmCheckBox.isSelected() || confirmMasterPassword()) {
                confirmCheckBox.setForeground(Color.black);
                if (identifier.length() > 0) {
                    String generated = pinCheckBox.isSelected()
                            ? generatePIN(master, identifier)
                            : generatePassword(master, identifier);
                    passwordField.setText(generated);
                } else {
                    passwordField.setText("");
                }
            } else {
                confirmCheckBox.setForeground(Color.red);
                passwordField.setText("");
            }
        } else {
            confirmCheckBox.setForeground(Color.black);
            passwordField.setText("");
        }
        Arrays.fill(master, '\0');
    }

    private void identifierFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_identifierFieldActionPerformed
        generate();
        copyToClipboard(passwordField.getText());
    }//GEN-LAST:event_identifierFieldActionPerformed

    @Override
    /**
     * Gives user the option to clear clipboard.
     */
    public void dispose() {
        int option = JOptionPane.showConfirmDialog(this, "Clear clipboard?",
                null, JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.CLOSED_OPTION) return;
        if (option == JOptionPane.YES_OPTION) copyToClipboard("");
        super.dispose();
    }

    /**
     * Sets the contents of the system clipboard to content.
     * @param content
     */
    private static void copyToClipboard(String content) {
        Toolkit.getDefaultToolkit().getSystemClipboard().
                setContents(new StringSelection(content), null);
    }

    private void copyPasswordButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_copyPasswordButtonActionPerformed
        copyToClipboard(passwordField.getText());
    }//GEN-LAST:event_copyPasswordButtonActionPerformed

    private void clearClipboardButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_clearClipboardButtonActionPerformed
        copyToClipboard("");
    }//GEN-LAST:event_clearClipboardButtonActionPerformed

    /**
     * Gets the text of a button for use in the about text.
     * @param button the button to get text from
     * @return the button's text, in quotes
     */
    private static String text(AbstractButton button) {
        return "\"" + button.getText() + "\"";
    }

    /**
     * Creates a component that looks like a JLabel, but has selectable and
     * copyable text.
     * @param text the text for the component to display
     * @return the component
     */
    private static JComponent selectableLabel(String text) {
        JTextField selectableLabel = new JTextField(text);
        selectableLabel.setEditable(false);
        selectableLabel.setBackground(null);
        selectableLabel.setBorder(null);
        return selectableLabel;
    }

    private void aboutButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aboutButtonActionPerformed
        final Object[] message = {
            "Multipass " + VERSION + " Copyright 2015 Ari Zerner.", "\n",
            "This software may be used and modified for any purpose, provided",
            "credit for its creation is not given to anyone but the copyright",
            "holder and the copyright holder is not given credit for any",
            "modifications for which he was not responsible.", "\n",
            "If you like Multipass, please consider donating!",
            selectableLabel("Paypal: multipassdonate@gmail.com"),
            selectableLabel("Bitcoin: 14cMKhqkgdp6bkqTojjjmwX67jKFyUsiZq"), "\n",
            "Multipass is a tool that allows you to easily generate a secure",
            "password or PIN from a master password and a use identifier",
            "(e.g. a website name). To use it, type your master password and use",
            "identifier in their respective fields, and then either press",
            text(copyPasswordButton) + " or check " + text(showCheckBox) + ".",
            "To generate a PIN instead of a password, simply check",
            text(pinCheckBox) + ".",
            "It is recommended that you set your master password as the",
            "confirmation password so that Multipass can check whether you have",
            "entered your master password correctly. To do this, press",
            text(setConfirmButton) + " and enter your master password. If you",
            "don't set a confirmation password, you will need to uncheck",
            text(confirmCheckBox) + ".",
            "\n", "How it works:", "\n",
            "To generate passwords and PINs, Multipass concatenates the master",
            "password and the identifier, separated by a space. It then uses the",
            GENERATION_ALGORITHM + " algorithm to hash the concatenation.",
            "To make a password, Multipass represents the hash as a lowercase",
            "hex string and concatenates the first 16 characters to the header,",
            "which is \"" + PASSWORD_HEADER + "\" (" + HEADER_MNEMONIC + ").",
            "To make a PIN, Multipass represents the hash as an unsigned decimal",
            "integer, and uses the last 4 digits, padding with zeros if necessary."
        };
        JOptionPane.showMessageDialog(this, message,
                "About Multipass",
                JOptionPane.INFORMATION_MESSAGE);
    }//GEN-LAST:event_aboutButtonActionPerformed

    private void masterFieldKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_masterFieldKeyReleased
        generate();
    }//GEN-LAST:event_masterFieldKeyReleased

    private void identifierFieldKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_identifierFieldKeyReleased
        generate();
    }//GEN-LAST:event_identifierFieldKeyReleased

    private void setConfirmButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setConfirmButtonActionPerformed
        JPasswordField confirmField = new JPasswordField();
        if (JOptionPane.showConfirmDialog(this, new Object[]{
            "Enter confirmation password:",
            confirmField,
            "It's important that you choose a master password",
            "that is both strong and easy to remember!"},
                "Set Confirmation Password", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION) {
            String salt = "" + new SecureRandom().nextLong();
            char[] confirmPassword = confirmField.getPassword();
            String hash = printHexBinary(
                    generateHash(confirmPassword, salt, CONFIRMATION_ALGORITHM))
                    .substring(0, CONFIRMATION_HASH_LENGTH);
            Arrays.fill(confirmPassword, '\0');
            confirmPreferences.put(CONFIRMATION_HASH_KEY, hash);
            confirmPreferences.put(CONFIRMATION_SALT_KEY, salt);
            generate();
        }
    }//GEN-LAST:event_setConfirmButtonActionPerformed

    private void identifierFieldKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_identifierFieldKeyPressed
        generate();
    }//GEN-LAST:event_identifierFieldKeyPressed

    private void masterFieldKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_masterFieldKeyPressed
        generate();
    }//GEN-LAST:event_masterFieldKeyPressed

    private void clearTimeSpinnerStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_clearTimeSpinnerStateChanged
        int clearTime = (Integer) clearTimeSpinner.getValue();
        clearTimer.setInitialDelay(MILLIS_PER_MINUTE * clearTime);
        if (clearCheckbox.isSelected()) clearTimer.restart();
        clearTimerPreferences.putInt(CLEAR_TIME_KEY, clearTime);
        String toolTipText
                = "Automatically clear the master password, use identifier, and "
                + "generated password if you are inactive for " + clearTime
                + " minutes.";
        clearCheckbox.setToolTipText(toolTipText);
        clearTimerMinutesLabel.setToolTipText(toolTipText);
    }//GEN-LAST:event_clearTimeSpinnerStateChanged

    private void clearCheckboxStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_clearCheckboxStateChanged
        boolean clearEnabled = clearCheckbox.isSelected();
        if (clearEnabled) {
            clearTimer.restart();
        } else {
            clearTimer.stop();
        }
        clearTimerPreferences.putBoolean(CLEAR_ENABLED_KEY, clearEnabled);
    }//GEN-LAST:event_clearCheckboxStateChanged

    private void confirmCheckBoxStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_confirmCheckBoxStateChanged
        generate();
    }//GEN-LAST:event_confirmCheckBoxStateChanged

    private void showCheckBoxStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_showCheckBoxStateChanged
        passwordField.setEchoChar(showCheckBox.isSelected() ? '\0'
                : defaultEchoChar);
    }//GEN-LAST:event_showCheckBoxStateChanged

    private void pinCheckBoxStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_pinCheckBoxStateChanged
        generate();
    }//GEN-LAST:event_pinCheckBoxStateChanged

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                MultiPass multiPass = new MultiPass();
                multiPass.setVisible(true);
                multiPass.setResizable(false);
                //putting setResizable after setVisible fixes a bug where
                //the frame would go to the bottom of the screen on startup
                //the bug was found on a Mac running OSX 10.10.4
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton aboutButton;
    private javax.swing.JCheckBox clearCheckbox;
    private javax.swing.JButton clearClipboardButton;
    private javax.swing.JSpinner clearTimeSpinner;
    private javax.swing.JLabel clearTimerMinutesLabel;
    private javax.swing.JCheckBox confirmCheckBox;
    private javax.swing.JButton copyPasswordButton;
    private javax.swing.JTextField identifierField;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPasswordField masterField;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JCheckBox pinCheckBox;
    private javax.swing.JButton setConfirmButton;
    private javax.swing.JCheckBox showCheckBox;
    // End of variables declaration//GEN-END:variables
}
