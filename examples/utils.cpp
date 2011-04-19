#include "interface.h"

char *wxStringChar(wxString str)
{
	char *tmp = NULL;
	tmp = (char *)malloc( (wxStrlen(str)) * sizeof(char *));
	strcpy( tmp, (const char*)str.mb_str(wxConvUTF8) );

	return tmp;
}

wxString selectFileName(wxFrame *frame, int savedlg) {
	wxFileDialog *dlg;
	long flags = wxFD_OPEN | wxFD_FILE_MUST_EXIST;

	if (savedlg)
		flags = wxFD_SAVE | wxFD_OVERWRITE_PROMPT;

	dlg = new wxFileDialog(frame, wxFileSelectorPromptStr, wxEmptyString, wxEmptyString, wxFileSelectorDefaultWildcardStr, flags);
	if (dlg->ShowModal() == wxID_OK)
		return dlg->GetPath();

	return wxEmptyString;
}

