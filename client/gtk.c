/*

  Copyright (c) 2009-2010 Samuel Lidén Borell <samuel@slbdata.se>
 
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
#include <glib.h>
#include <assert.h>

#include <locale.h>
#include <libintl.h>

#include <unistd.h> // For STDIN_FILENO

#include "../common/defines.h"
#include "bankid.h"
#include "keyfile.h"
#include "platform.h"

#define _(string) gettext(string)

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

/* Authentication */
static GtkDialog *signDialog;
static GtkLabel *operationLabel;
static GtkTextView *signText;
static GtkComboBox *signaturesCombo;
static GtkEntry *passwordEntry;
static GtkButton *signButton;
static GtkLabel *signButtonLabel;

static GtkWidget *signLabel;
static GtkWidget *signScroller;

static char *currentSubjectFilter;


static void showMessage(GtkMessageType type, const char *text) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(signDialog), GTK_DIALOG_DESTROY_WITH_PARENT,
        type, GTK_BUTTONS_CLOSE, "%s", text);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void validateDialog(GtkWidget *ignored1, gpointer *ignored2) {
    gtk_widget_set_sensitive(GTK_WIDGET(signButton),
                             (gtk_combo_box_get_active(signaturesCombo) != -1));
}

static bool addSignatureFile(GtkListStore *signatures, const char *filename,
                             GtkTreeIter *iter) {
    int fileLen;
    char *fileData;
    platform_readFile(filename, &fileData, &fileLen);
    
    int personCount;
    KeyfileSubject **people = NULL;
    keyfile_listPeople(fileData, fileLen, &people, &personCount);
    
    for (int i = 0; i < personCount; i++) {
        if (keyfile_matchSubjectFilter(people[i], currentSubjectFilter)) {
            char *displayName = keyfile_getDisplayName(people[i]);
            
            gtk_list_store_append(signatures, iter);
            gtk_list_store_set(signatures, iter,
                               0, displayName,
                               1, people[i],
                               2, filename, -1);
            
            free(displayName);
        } else {
            // The subject isn't needed
            keyfile_freeSubject(people[i]);
        }
    }
    free(people);
    memset(fileData, 0, fileLen);
    free(fileData);
    
    return (personCount != 0);
}

static bool removeSignatureFile(GtkTreeModel *signatures, const char *filename) {
    GtkTreeIter iter = { .stamp = 0 };
    
    bool valid = gtk_tree_model_get_iter_first(signatures, &iter);
    while (valid) {
        char *displayName;
        char *otherFilename;
        KeyfileSubject *person;
        
        gtk_tree_model_get(signatures, &iter,
                           0, &displayName,
                           1, &person,
                           2, &otherFilename, -1);
        if (!strcmp(filename, otherFilename)) {
            // Remove this signature
            free(displayName);
            free(otherFilename);
            keyfile_freeSubject(person);
            valid = gtk_list_store_remove(GTK_LIST_STORE(signatures), &iter);
        } else {
            valid = gtk_tree_model_iter_next(signatures, &iter);
        }
    }
    
    return false;
}

static void selectDefaultSignature() {
    GtkTreeModel *model = gtk_combo_box_get_model(signaturesCombo);
    GtkTreeIter iter = { .stamp = 0 };
    
    if (gtk_tree_model_get_iter_first(model, &iter) &&
        !gtk_tree_model_iter_next(model, &iter)) {
        // There's only one item, select it
        gtk_tree_model_get_iter_first(model, &iter);
        gtk_combo_box_set_active_iter(signaturesCombo, &iter);
    }
}

void platform_startSign(const char *url, const char *hostname, const char *ip,
                        const char *subjectFilter, unsigned long parentWindowId) {
    
    currentSubjectFilter = (subjectFilter != NULL ?
                            strdup(subjectFilter) : NULL);
    
    GtkBuilder *builder = gtk_builder_new();
    GError *error = NULL;
    
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
    
    // Create a GtkListStore of (displayname, person, filename) tuples
    GtkListStore *signatures = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_STRING);
    GtkTreeIter iter = { .stamp = 0 };
    
    // Look for P12s in ~/cbt
    PlatformDirIter *dir = platform_openKeysDir();
    if (dir) {
        while (platform_iterateDir(dir)) {
            char *filename = platform_currentPath(dir);
            addSignatureFile(signatures, filename, &iter);
            free(filename);
        }
        platform_closeDir(dir);
    }
    
    signaturesCombo = GTK_COMBO_BOX(gtk_builder_get_object(builder, "signature_combo"));
    gtk_combo_box_set_model(signaturesCombo, GTK_TREE_MODEL(signatures));
    g_object_unref(signatures);
    
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(signaturesCombo),
                               renderer, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(signaturesCombo),
                                   renderer, "text", 0, (char *)NULL);
    
    // Used to dim the "Sign" button when no signature has been selected
    g_signal_connect(G_OBJECT(signaturesCombo), "changed",
                     G_CALLBACK(validateDialog), NULL);
    
    selectDefaultSignature();
    
    passwordEntry = GTK_ENTRY(gtk_builder_get_object(builder, "password_entry"));
    
    signDialog = GTK_DIALOG(gtk_builder_get_object(builder, "dialog_sign"));
    
    bool transientOk = false;
    if (parentWindowId != PLATFORM_NO_WINDOW) {
        GdkWindow *parent = gdk_window_foreign_new((GdkNativeWindow)parentWindowId);
        if (parent != NULL) {
            gtk_widget_realize(GTK_WIDGET(signDialog));
            // Only available in GTK 2.14+
            //GdkWindow *ourWindow = gtk_widget_get_window(GTK_WINDOW(signDialog));
            GdkWindow *ourWindow = GTK_WIDGET(signDialog)->window;
            if (ourWindow != NULL) {
                gdk_window_set_transient_for(ourWindow, parent);
                transientOk = true;
                //g_object_unref(G_OBJECT(ourWindow));
            }
            g_object_unref(G_OBJECT(parent));
        }
    }
    
    if (!transientOk) {
        gtk_window_set_keep_above(GTK_WINDOW(signDialog), TRUE);
    }
    
    platform_setMessage(NULL);
    validateDialog(NULL, NULL);
    
    gtk_window_set_modal(GTK_WINDOW(signDialog), TRUE);
    gtk_widget_show(GTK_WIDGET(signDialog));
}

void platform_endSign() {
    // Free all subjects in the list
    GtkTreeModel *model = gtk_combo_box_get_model(signaturesCombo);
    GtkTreeIter iter = { .stamp = 0 };
    
    bool valid = gtk_tree_model_get_iter_first(model, &iter);
    while (valid) {
        KeyfileSubject *subject;
        gtk_tree_model_get(model, &iter,
                           1, &subject, -1);
        keyfile_freeSubject(subject);
        valid = gtk_tree_model_iter_next(model, &iter);
    }
    
    gtk_widget_destroy(GTK_WIDGET(signDialog));
    free(currentSubjectFilter);
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
        gtk_label_set_label(GTK_LABEL(operationLabel), _("<big><b>Signing on: </b></big>"));
        gtk_label_set_label(GTK_LABEL(signButtonLabel), _("_Sign"));
    }
}


static void selectExternalFile() {
    bool ok = true;
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(gtk_file_chooser_dialog_new(
            _("Select external identity file"), GTK_WINDOW(signDialog),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
            (char *)NULL));
    if (gtk_dialog_run(GTK_DIALOG(chooser)) == GTK_RESPONSE_ACCEPT) {
        gchar *filename = gtk_file_chooser_get_filename(chooser);
        GtkTreeModel *signatures = gtk_combo_box_get_model(signaturesCombo);
        
        removeSignatureFile(signatures, filename);
        
        // Add an item to the signatures list and select it
        GtkTreeIter iter = { .stamp = 0 };
        ok = addSignatureFile(GTK_LIST_STORE(signatures), filename, &iter);
        if (ok) gtk_combo_box_set_active_iter(signaturesCombo, &iter);
        
        g_free(filename);
    }
    gtk_widget_destroy(GTK_WIDGET(chooser));
    
    if (!ok) {
        // TODO check the real reason for the error
        showMessage(GTK_MESSAGE_ERROR, (currentSubjectFilter != NULL ?
            _("No matching identities found") :
            _("Invalid file format")));
    }
}

#define RESPONSE_OK       10
#define RESPONSE_CANCEL   20
#define RESPONSE_EXTERNAL 30

/**
 * Waits for the user to fill in the dialog, and loads the P12 file for
 * the selected subject.
 */
bool platform_sign(char **signature, int *siglen, KeyfileSubject **person,
                   char **password, int password_maxlen) {
    guint response;

    // Restrict the password to the length of the preallocated
    // password buffer
    gtk_entry_set_max_length(passwordEntry, password_maxlen-1);

    while ((response = gtk_dialog_run(signDialog)) == RESPONSE_EXTERNAL) {
        // User pressed "External file..."
        selectExternalFile();
    }
    
    if (response == RESPONSE_OK) {
        // User pressed "Log in" or "Sign"
        GtkTreeIter iter = { .stamp = 0 };
        
        *signature = NULL;
        *siglen = 0;
        *person = NULL;
        
        if (gtk_combo_box_get_active_iter(signaturesCombo, &iter)) {
            const KeyfileSubject *selectedPerson;
            char *filename;
            GtkTreeModel *model = gtk_combo_box_get_model(signaturesCombo);
            gtk_tree_model_get(model, &iter,
                               1, &selectedPerson,
                               2, &filename, -1);
            *person = keyfile_duplicateSubject(selectedPerson);
            
            // Read .p12 file
            platform_readFile(filename, signature, siglen);
            free(filename);
        }
        
        // Copy the password to the secure buffer
        strncpy(*password, gtk_entry_get_text(passwordEntry), password_maxlen-1);
        // Be sure to terminate this under all circumstances
        *password[password_maxlen-1] = '\0';
        return true;
    } else {
        // User pressed cancel or closed the dialog
        return false;
    }
}

void platform_signError() {
    showMessage(GTK_MESSAGE_ERROR, _("The identity file couldn't be decoded. Maybe the password is incorrect?"));
}

void platform_versionExpiredError() {
    showMessage(GTK_MESSAGE_ERROR, _("This software version has expired, and "
                "will probably not be accepted on all web sites.\n"
                "\n"
                "Please download a newer version (if available), or use "
                "the officially supported software (Nexus Personal) instead."));
}


