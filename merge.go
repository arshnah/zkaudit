package zkaudit

func MergeHARs(hars ...*HAR) *HAR {
	out := &HAR{}
	for _, h := range hars {
		if h == nil {
			continue
		}
		out.Log.Entries = append(out.Log.Entries, h.Log.Entries...)
	}
	return out
}
