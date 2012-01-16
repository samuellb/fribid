/*

  Copyright (c) 2009-2011 Samuel Lidén Borell <samuel@slbdata.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#define _BSD_SOURCE 1
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <glib.h>
#include <assert.h>
#include <errno.h>

#include <locale.h>
#include <libintl.h>

#include <unistd.h> // For STDIN_FILENO

#include "../common/defines.h"
#include "backend.h"
#include "bankid.h"
#include "platform.h"
#include "misc.h"

#define _(string) gettext(string)
#define translatable(string) (string)

static const char *const errorStrings[] = {
    // TokenError_Success
    NULL,
    // TokenError_Unknown
    translatable("An unknown error occurred"),
    // TokenError_NotImplemented
    translatable("Not implemented yet"),
    
    // File errors
    // TokenError_FileNotReadable
    translatable("The file could not be read"),
    // TokenError_CantCreateFile
    translatable("The file could not be saved"),
    // TokenError_BadFile
    translatable("Invalid file format"),
    // TokenError_BadPassword,
    translatable("Incorrect password"),
    
    // Smart card errors
    // TokenError_BadPin
    translatable("Incorrect PIN"),
    
    // Key generation errors
    //TokenError_NoRandomState,
    translatable("No random state available (/dev/(u)random must exist)"),
};


void platform_init(int *argc, char ***argv) {
    setlocale(LC_ALL, "");
    bindtextdomain(BINNAME, LOCALEDIR);
    textdomain(BINNAME);
    
    gtk_init(argc, argv);
}

void platform_leaveMainloop() {
    gtk_main_quit();
}

static PlatformPipeFunction* currentPipeFunction = NULL;

static gboolean pipeCallback(GIOChannel *source,
                             GIOCondition condition, gpointer data) {
    currentPipeFunction();
    return TRUE;
}

void platform_setupPipe(PlatformPipeFunction *pipeFunction) {
    assert(currentPipeFunction == NULL);
    currentPipeFunction = pipeFunction;
    
    GIOChannel *stdinChannel = g_io_channel_unix_new(STDIN_FILENO);
    g_io_add_watch(stdinChannel,
                   G_IO_IN | G_IO_HUP | G_IO_ERR, pipeCallback, NULL);
    g_io_channel_unref(stdinChannel);
}

void platform_mainloop() {
    gtk_main();
}

/* Sign/Authenticate dialog controls and state */
static GtkDialog *signDialog;
static GtkLabel *operationLabel;
static GtkTextView *signText;
static GtkComboBox *tokenCombo;
static GtkEntry *passwordEntry;
static GtkButton *signButton;
static GtkLabel *signButtonLabel;

static GtkWidget *signLabel;
static GtkWidget *signScroller;

static GtkInfoBar *info_bar;
static GtkLabel *info_label;

static GtkListStore *tokens;
static BackendNotifier *notifier;
static bool signDialogShown;

/* Password choice and key generation dialog */
static GtkDialog *keygenDialog;
static GtkEntry *keygenPasswordEntry;
static GtkEntry *keygenRepeatPasswordEntry;
static int keygenPasswordMinLen;
static int keygenPasswordMinDigits;
static int keygenPasswordMinNonDigits;
static bool keygenDialogShown;

static GtkDialog *activeDialog;

/**
 * Makes a dialog window stay above it's parent window.
 */
static void makeDialogTransient(GtkDialog *dialog, unsigned long parentWindowId) {
    bool transientOk = false;
    
    if (parentWindowId != PLATFORM_NO_WINDOW) {
#if GTK_CHECK_VERSION(2, 24, 0)
        GdkDisplay *display = gdk_display_get_default();
        GdkWindow *parent = gdk_x11_window_foreign_new_for_display(display,
            (Window)parentWindowId);
#else
        GdkWindow *parent = gdk_window_foreign_new((GdkNativeWindow)parentWindowId);
#endif
        if (parent != NULL) {
            gtk_widget_realize(GTK_WIDGET(dialog));
            GdkWindow *ourWindow = gtk_widget_get_window(GTK_WIDGET(dialog));
            if (ourWindow != NULL) {
                gdk_window_set_transient_for(ourWindow, parent);
                transientOk = true;
                //g_object_unref(G_OBJECT(ourWindow));
            }
            g_object_unref(G_OBJECT(parent));
        }
    }
    
    if (!transientOk) {
        gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
    }
}

static void showMessage(GtkMessageType type, const char *text) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(activeDialog), GTK_DIALOG_DESTROY_WITH_PARENT,
        type, GTK_BUTTONS_CLOSE, "%s", text);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void hide_message () {
    gtk_widget_hide (GTK_WIDGET (info_bar));
}

static void show_inline_message (GtkMessageType message_type, const char *message) {
    gtk_widget_show(GTK_WIDGET (info_bar));
    gtk_info_bar_set_message_type(GTK_INFO_BAR (info_bar),
                                  message_type);
    gtk_label_set_text(info_label, message);
}

static void validateDialog(GtkWidget *ignored1, gpointer *ignored2) {
    gtk_widget_set_sensitive(GTK_WIDGET(signButton),
                             (gtk_combo_box_get_active(tokenCombo) != -1));
    hide_message();
    if (gtk_combo_box_get_active(tokenCombo) != -1) {
        GtkTreeIter iter = { .stamp = 0 };

        Token *token;
        token = NULL;

        if (gtk_combo_box_get_active_iter(tokenCombo, &iter)) {
            gtk_tree_model_get(GTK_TREE_MODEL(tokens), &iter,
                               1, &token, -1);
            gtk_widget_set_sensitive (GTK_WIDGET (passwordEntry), token_getStatus(token) != TokenStatus_NeedPIN);
            if (token_getStatus(token) == TokenStatus_NeedPIN) {
                show_inline_message (GTK_MESSAGE_INFO, _("Please enter PIN on pinpad"));
            }
        }
    }
}

static TokenError addTokenFile(const char *filename) {
    int fileLen;
    char *fileData;
    
    if (!platform_readFile(filename, &fileData, &fileLen))
        return TokenError_FileNotReadable;
    
    TokenError error = backend_addFile(notifier, fileData, fileLen,
                                       strdup(filename));
    
    guaranteed_memset(fileData, 0, fileLen);
    free(fileData);
    
    return error;
}

/**
 * Tells the backend to remove a file token.
 */
static void removeTokenFile(const char *filename) {
    GtkTreeIter iter = { .stamp = 0 };
    GtkTreeModel *model = GTK_TREE_MODEL(tokens);
    
    bool valid = gtk_tree_model_get_iter_first(model, &iter);
    while (valid) {
        char *displayName;
        char *otherFilename;
        Token *token;
        
        gtk_tree_model_get(model, &iter,
                           0, &displayName,
                           1, &token,
                           2, &otherFilename, -1);
        if (!strcmp(filename, otherFilename)) {
            // Remove this token
            token_remove(token);
            free(displayName);
            free(otherFilename);
            valid = gtk_list_store_remove(tokens, &iter);
        } else {
            valid = gtk_tree_model_iter_next(model, &iter);
        }
    }
}

static void selectDefaultToken() {
    GtkTreeModel *model = GTK_TREE_MODEL(tokens);
    GtkTreeIter iter = { .stamp = 0 };
    
    if (gtk_tree_model_get_iter_first(model, &iter) &&
        !gtk_tree_model_iter_next(model, &iter)) {
        // There's only one item, select it
        gtk_tree_model_get_iter_first(model, &iter);
        gtk_combo_box_set_active_iter(tokenCombo, &iter);
    }
}

void platform_startSign(const char *url, const char *hostname, const char *ip,
                        unsigned long parentWindowId) {
    
    GtkBuilder *builder = gtk_builder_new();
    GError *error = NULL;
    GtkBox *box;
    GtkContainer *content_area;
    
    if (!gtk_builder_add_from_file(builder, UI_GTK_XML, &error)) {
        fprintf(stderr, BINNAME ": Failed to open GtkBuilder XML: %s\n", error->message);
        g_error_free(error);
        return;
    }
    
    signButton = GTK_BUTTON(gtk_builder_get_object(builder, "button_sign"));
    signButtonLabel = GTK_LABEL(gtk_builder_get_object(builder, "buttonlabel_sign"));
    
    operationLabel = GTK_LABEL(gtk_builder_get_object(builder, "header_op"));
    gtk_label_set_text(GTK_LABEL(gtk_builder_get_object(builder, "header_domain")),
                       hostname);
    
    signLabel = GTK_WIDGET(gtk_builder_get_object(builder, "sign_label"));
    signScroller = GTK_WIDGET(gtk_builder_get_object(builder, "sign_scroller"));
    signText = GTK_TEXT_VIEW(gtk_builder_get_object(builder, "sign_text"));
    
    // Create a GtkListStore of (displayname, token, filename) tuples
    tokens = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_STRING);
    
    tokenCombo = GTK_COMBO_BOX(gtk_builder_get_object(builder, "signature_combo"));
    gtk_combo_box_set_model(tokenCombo, GTK_TREE_MODEL(tokens));
    
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(tokenCombo),
                               renderer, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(tokenCombo),
                                   renderer, "text", 0, (char *)NULL);
    
    // Set displayname as the sort column
    GtkTreeSortable *sortable = GTK_TREE_SORTABLE(tokens);
    gtk_tree_sortable_set_sort_column_id(sortable, 0, GTK_SORT_ASCENDING);
    
    // Used to dim the "Sign" button when no signature has been selected
    g_signal_connect(G_OBJECT(tokenCombo), "changed",
                     G_CALLBACK(validateDialog), NULL);
    
    passwordEntry = GTK_ENTRY(gtk_builder_get_object(builder, "password_entry"));

    info_bar = GTK_INFO_BAR(gtk_info_bar_new());
    info_label = GTK_LABEL(gtk_label_new(""));

    content_area = GTK_CONTAINER (gtk_info_bar_get_content_area(GTK_INFO_BAR (info_bar)));
    gtk_container_add(GTK_CONTAINER(content_area), GTK_WIDGET (info_label));
    gtk_widget_show(GTK_WIDGET(info_label));

    box = GTK_BOX(gtk_builder_get_object(builder, "vbox1"));
    gtk_box_pack_end(box, GTK_WIDGET (info_bar), TRUE, FALSE, 2);

    activeDialog = signDialog = GTK_DIALOG(gtk_builder_get_object(builder, "dialog_sign"));
    
    makeDialogTransient(signDialog, parentWindowId);
    
    platform_setMessage(NULL);
    validateDialog(NULL, NULL);
    
    gtk_window_set_modal(GTK_WINDOW(signDialog), TRUE);
    signDialogShown = false;
}

void platform_endSign() {
    // Remove all manually added tokens
    GtkTreeModel *model = GTK_TREE_MODEL(tokens);
    GtkTreeIter iter = { .stamp = 0 };
    
    bool valid = gtk_tree_model_get_iter_first(model, &iter);
    while (valid) {
        char *displayName, *filename;
        Token *token;
        
        gtk_tree_model_get(model, &iter,
                           0, &displayName,
                           1, &token,
                           2, &filename, -1);
        token_remove(token);
        free(displayName);
        free(filename);
        valid = gtk_tree_model_iter_next(model, &iter);
    }
    
    gtk_widget_destroy(GTK_WIDGET(signDialog));
    g_object_unref(tokens);
}

void platform_setMessage(const char *message) {
    if (message == NULL) {
        gtk_widget_hide(signLabel);
        gtk_widget_hide(signScroller);
        
        gtk_window_set_title(GTK_WINDOW(signDialog), _("Identification"));
        gtk_label_set_label(GTK_LABEL(operationLabel), _("<big><b>Prove identity to: </b></big>"));
        gtk_label_set_label(signButtonLabel, _("_Prove identity"));
    } else {
        GtkTextBuffer *textBuffer = gtk_text_view_get_buffer(signText);
        gtk_text_buffer_set_text(textBuffer, message, strlen(message));
        
        gtk_widget_show(signLabel);
        gtk_widget_show(signScroller);
        
        gtk_window_set_title(GTK_WINDOW(signDialog), _("Signing"));
        gtk_label_set_label(GTK_LABEL(operationLabel), _("<big><b>Create signature on: </b></big>"));
        gtk_label_set_label(GTK_LABEL(signButtonLabel), _("_Sign"));
    }
}

/**
 * Sets the backend notifier to use for receiving token insertion/removal
 * events and manually requesting token files to be added.
 */
void platform_setNotifier(BackendNotifier *notifierToUse) {
    notifier = notifierToUse;
}

/**
 * Add  from the key directories
 */
void platform_addKeyDirectories() {
    char** paths;
    size_t len;
    
    // Look for P12s in ~/cbt and ~/.cbt
    platform_keyDirs(&paths, &len);
    for (size_t i = 0; i <= len; i++) {
        PlatformDirIter *dir = platform_openKeysDir(paths[i]);
        if (dir) {
            while (platform_iterateDir(dir)) {
                char *filename = platform_currentPath(dir);
                
                if (!strstr(filename, ".tmp")) {
                    addTokenFile(filename);
                }
                
                free(filename);
            }
            platform_closeDir(dir);
        }
        free(paths[i]);
    }
}

static gboolean addTokenFunc(gpointer ptr) {
    Token *token = (Token*)ptr;
    GtkTreeIter iter = { .stamp = 0 };
    const char *filename = (char *)token_getTag(token);
    
    // Check for errors
    TokenError error = token_getLastError(token);
    if (error) {
        platform_showError(error);
        return FALSE;
    }
    
    // Add token
    gtk_list_store_append(tokens, &iter);
    gtk_list_store_set(tokens, &iter,
                       0, token_getDisplayName(token),
                       1, token,
                       2, filename, -1);
    
    if (filename) {
        // The token was manually added. Select it.
        gtk_combo_box_set_active_iter(tokenCombo, &iter);
    }
    
    return FALSE;
}

static gboolean removeTokenFunc(gpointer ptr) {
    Token *token = (Token*)ptr;
    GtkTreeModel *model = GTK_TREE_MODEL(tokens);
    GtkTreeIter iter = { .stamp = 0 };
    
    bool valid = gtk_tree_model_get_iter_first(model, &iter);
    while (valid) {
        Token *listToken;
        gtk_tree_model_get(model, &iter,
                           1, &listToken, -1);
        valid = (listToken == token ?
            gtk_list_store_remove(tokens, &iter) :
            gtk_tree_model_iter_next(model, &iter));
    }
    
    return FALSE;
}

/**
 * Adds a token to the list of identity tokens. This function should be called
 * after platform_startSign.
 */
void platform_addToken(Token *token) {
    g_idle_add_full(G_PRIORITY_HIGH, addTokenFunc, token, NULL);
}

/**
 * Removes a token from the list of identity tokens. This function should only
 * be called after platform_startSign has been called.
 */
void platform_removeToken(Token *token) {
    g_idle_add_full(G_PRIORITY_HIGH, removeTokenFunc, token, NULL);
}


static void selectExternalFile() {
    TokenError error = TokenError_Success;
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(gtk_file_chooser_dialog_new(
            _("Select external identity file"), GTK_WINDOW(signDialog),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
            (char *)NULL));
    activeDialog = GTK_DIALOG(chooser);
    
    while (gtk_dialog_run(GTK_DIALOG(chooser)) == GTK_RESPONSE_ACCEPT) {
        gchar *filename = gtk_file_chooser_get_filename(chooser);
        
        removeTokenFile(filename);
        
        // Add an item to the token list and select it
        error = addTokenFile(filename);
        
        g_free(filename);
        if (error) platform_showError(error);
        else break;
    }
    
    activeDialog = signDialog;
    gtk_widget_destroy(GTK_WIDGET(chooser));
}

#define RESPONSE_OK       10
#define RESPONSE_CANCEL   20
#define RESPONSE_EXTERNAL 30

/**
 * Waits for the user to fill in the dialog, and loads the P12 file for
 * the selected subject.
 */
bool platform_sign(Token **token, char *password, int password_maxlen) {
    guint response;

    // Restrict the password to the length of the preallocated
    // password buffer
    gtk_entry_set_max_length(passwordEntry, password_maxlen-1);
    
    if (!signDialogShown) {
        selectDefaultToken();
        gtk_widget_show(GTK_WIDGET(signDialog));
        signDialogShown = true;
    }
    
    while ((response = gtk_dialog_run(signDialog)) == RESPONSE_EXTERNAL) {
        // User pressed "External file..."
        selectExternalFile();
    }
    
    if (response == RESPONSE_OK) {
        // User pressed "Log in" or "Sign"
        GtkTreeIter iter = { .stamp = 0 };
        
        *token = NULL;
        
        if (gtk_combo_box_get_active_iter(tokenCombo, &iter)) {
            gtk_tree_model_get(GTK_TREE_MODEL(tokens), &iter,
                               1, token, -1);
        }

        // Copy the password to the secure buffer
        strncpy(password, gtk_entry_get_text(passwordEntry), password_maxlen-1);
        // Be sure to terminate this under all circumstances
        password[password_maxlen-1] = '\0';
        return true;
    } else {
        // User pressed cancel or closed the dialog
        return false;
    }
}


void platform_startChoosePassword(const char *name, unsigned long parentWindowId) {
    
    GtkBuilder *builder = gtk_builder_new();
    GError *error = NULL;
    
    if (!gtk_builder_add_from_file(builder, UI_GTK_XML, &error)) {
        fprintf(stderr, BINNAME ": Failed to open GtkBuilder XML: %s\n", error->message);
        g_error_free(error);
        return;
    }
    
    gtk_label_set_text(GTK_LABEL(gtk_builder_get_object(builder, "label_keygen_name")),
                       name);
    
    keygenPasswordEntry = GTK_ENTRY(gtk_builder_get_object(builder, "entry_keygen_password"));
    keygenRepeatPasswordEntry = GTK_ENTRY(gtk_builder_get_object(builder, "entry_keygen_repeat"));
    
    activeDialog = keygenDialog = GTK_DIALOG(gtk_builder_get_object(builder, "dialog_keygen"));
    
    makeDialogTransient(keygenDialog, parentWindowId);
    
    gtk_window_set_modal(GTK_WINDOW(keygenDialog), TRUE);
    keygenDialogShown = false;
}

void platform_setPasswordPolicy(int minLength, int minNonDigits, int minDigits) {
    keygenPasswordMinLen = minLength;
    keygenPasswordMinNonDigits = minNonDigits;
    keygenPasswordMinDigits = minDigits;
}

void platform_endChoosePassword() {
    gtk_widget_destroy(GTK_WIDGET(keygenDialog));
    
}

static bool weakPassword(int length, int minimum, const char *format) {
    if (length < minimum) {
        char *error = rasprintf(format, minimum);
        showMessage(GTK_MESSAGE_ERROR, error);
        g_free(error);
        return TRUE;
    }
    return FALSE;
}

bool platform_choosePassword(char *password, long password_maxlen) {
    // Restrict the password to the length of the preallocated
    // password buffer
    gtk_entry_set_max_length(keygenPasswordEntry, password_maxlen-1);
    gtk_entry_set_max_length(keygenRepeatPasswordEntry, password_maxlen-1);
    
    if (!keygenDialogShown) {
        gtk_widget_show(GTK_WIDGET(keygenDialog));
        keygenDialogShown = true;
    }
    
    for (;;) {
        gint response = gtk_dialog_run(keygenDialog);
        
        if (response == GTK_RESPONSE_OK) {
            // Check if the passwords match
            
            // TODO disable the button when passwords don't match and show
            //      an explanation in an info bar, instead of showing an
            //      error dialog
            if (strcmp(gtk_entry_get_text(keygenPasswordEntry),
                       gtk_entry_get_text(keygenRepeatPasswordEntry))) {
                // Did not match
                showMessage(GTK_MESSAGE_ERROR, _("The passwords don't match!"));
                continue;
            }
            
            // Check password policy
            const char *pwtext = gtk_entry_get_text(keygenPasswordEntry);
            int pwlen = g_utf8_strlen(pwtext, -1);
            
            int numDigits = 0;
            int numNonDigits = 0;
            const char *c = pwtext;
            while (*c) {
                if (*c >= '0' && *c <= '9') numDigits++;
                else numNonDigits++;
                c = g_utf8_find_next_char(c, NULL);
            }
            
            if (weakPassword(pwlen, keygenPasswordMinLen,
                    ngettext("The password must be at least one character",
                             "The password must be at least %d characters",
                             keygenPasswordMinLen)) ||
                weakPassword(numNonDigits, keygenPasswordMinNonDigits,
                    ngettext("The password must have at least one character that is not a digit",
                             "The password must have at least %d characters that are not digits",
                             keygenPasswordMinNonDigits)) ||
                weakPassword(numDigits, keygenPasswordMinDigits,
                    ngettext("The password must have at least one digit",
                             "The password must have at least %d digits",
                             keygenPasswordMinDigits))) {
                // Not OK
                continue;
            }
            
            // Copy the password to the secure buffer
            strncpy(password, pwtext, password_maxlen-1);
            // Be sure to terminate this under all circumstances
            password[password_maxlen-1] = '\0';
            return true;
        } else {
            // User pressed cancel or closed the dialog
            return false;
        }
    }
}


void platform_showError(TokenError error) {
    assert(error != TokenError_Success);
    
    int lastErrno = errno;
    const char *text = gettext(errorStrings[error]);
    char *longText;
    
    switch (error) {
        case TokenError_FileNotReadable:
        case TokenError_CantCreateFile:
            longText = rasprintf("%s\n\n%s", text, g_strerror(lastErrno));
            showMessage(GTK_MESSAGE_ERROR, longText);
            g_free(longText);
            break;
        default:
            showMessage(GTK_MESSAGE_ERROR, text);
            break;
    }
}

void platform_versionExpiredError() {
    showMessage(GTK_MESSAGE_ERROR, _("This software version has expired, and "
                "will probably not be accepted on all web sites.\n"
                "\n"
                "Please download a newer version (if available), or use "
                "the officially supported software (Nexus Personal) instead."));
}


